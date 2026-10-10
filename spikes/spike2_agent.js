"use strict";

/*
 * Spike 2 agent — Stage 0 of the whatlicense pipeline, ported from the PIN
 * tool (`wl-extract/main.cpp`, Stage 0) to the Frida stack.
 *
 * Stage 0 recovers `lic_copy`: where the protection copies the mapped
 * license file to. The PIN original:
 *
 *   1. NtCreateFile/ZwCreateFile hook: an open whose path ends in
 *      "regkey.dat" is redirected to our (dummy) license file, and the
 *      opening thread is remembered as the main thread.
 *   2. MapViewOfFile hook: after the real call, if the first 8 bytes of the
 *      mapping equal the license file's first 8 bytes -> lic_mapped.
 *   3. While lic_mapped: every 1-byte write to memory on the main thread
 *      whose value equals the license head byte records its effective
 *      address as a candidate (PIN inserts this at IPOINT_AFTER, i.e. it
 *      reads the byte just written).
 *   4. UnmapViewOfFile hook: when the unmap target's first 8 bytes are the
 *      license head, search the candidates for one whose first 8 bytes now
 *      match -> that address is lic_copy.
 *
 * Frida differences that shaped this port:
 *   - A Stalker callout runs BEFORE the instruction, so the PIN trick of
 *     reading the just-written byte is impossible. Instead the byte about to
 *     be written is derived from the store's source operand (register or
 *     immediate), which yields the same candidate set.
 *   - MapViewOfFile/UnmapViewOfFile are Interceptor.attach hooks on the
 *     exports (no need to reimplement the call like PIN's
 *     RTN_ReplaceSignature).
 *   - Linux has no NtCreateFile; the same logic is exercised there through
 *     mmap/munmap (the local target opens the file itself), which is what
 *     makes this spike testable in seconds instead of only in CI.
 */

const HEAD_LEN = 8;

let plan = null;
let report = null;
let stats = null;
let followStart = 0;

const IS_WINDOWS = Process.platform === "windows";
const PTR_SIZE = Process.pointerSize;
const IS_IA32 = Process.arch === "ia32";
const PC_REG = IS_IA32 ? "eip" : "rip";
const SP_REG = IS_IA32 ? "esp" : "rsp";
const BP_REG = IS_IA32 ? "ebp" : "rbp";

function log(message) {
    console.log("spike2: " + message);
}

function emit(payload) {
    try {
        send(payload);
    } catch (e) {
        /* console output from a callout is not reliable; send() is */
    }
}

function hex(bytes) {
    const out = [];
    for (let i = 0; i < bytes.length; i++) {
        out.push(bytes[i].toString(16).padStart(2, "0"));
    }
    return out.join("");
}

function headMatches(pointer) {
    if (pointer === null || pointer.isNull()) {
        return false;
    }
    try {
        const bytes = new Uint8Array(pointer.readByteArray(HEAD_LEN));
        for (let i = 0; i < HEAD_LEN; i++) {
            if (bytes[i] !== plan.head[i]) {
                return false;
            }
        }
        return true;
    } catch (e) {
        return false;
    }
}

/* The byte a 1-byte store is about to write, from its source operand. */
const BYTE_REGISTERS = {
    al: ["eax", 0], cl: ["ecx", 0], dl: ["edx", 0], bl: ["ebx", 0],
    ah: ["eax", 8], ch: ["ecx", 8], dh: ["edx", 8], bh: ["ebx", 8],
    spl: ["esp", 0], bpl: ["ebp", 0], sil: ["esi", 0], dil: ["edi", 0],
    r8b: ["r8", 0], r9b: ["r9", 0], r10b: ["r10", 0], r11b: ["r11", 0],
    r12b: ["r12", 0], r13b: ["r13", 0], r14b: ["r14", 0], r15b: ["r15", 0]
};

function wideName(context, name) {
    if (context[name] !== undefined) {
        return name;
    }
    const wide = {
        eax: "rax", ebx: "rbx", ecx: "rcx", edx: "rdx",
        esi: "rsi", edi: "rdi", ebp: "rbp", esp: "rsp"
    }[name];
    if (wide !== undefined && context[wide] !== undefined) {
        return wide;
    }
    return name;
}

function writtenByte(info, context) {
    /* The store's value operand: operands[0] is the memory destination. */
    for (let i = 1; i < info.operands.length; i++) {
        const operand = info.operands[i];
        if (operand.type === "imm") {
            return operand.value & 0xff;
        }
        if (operand.type === "reg") {
            const entry = BYTE_REGISTERS[operand.value];
            if (entry === undefined) {
                return null; /* 32/64-bit source with a 1-byte dest: unusual */
            }
            const name = wideName(context, entry[0]);
            if (context[name] === undefined) {
                return null;
            }
            const value = context[name].toUInt32();
            return (value >>> entry[1]) & 0xff;
        }
    }
    return null;
}

function snapshot(insn) {
    const info = {
        address: insn.address.toString(),
        mnemonic: insn.mnemonic,
        opStr: insn.opStr,
        size: insn.size,
        next: insn.address.add(insn.size).toString(),
        operands: [],
        mem: null
    };
    for (const operand of insn.operands) {
        const entry = { type: operand.type, size: operand.size };
        if (operand.type === "mem") {
            const value = operand.value;
            entry.value = {
                base: value.base,
                index: value.index,
                scale: value.scale,
                disp: value.disp
            };
            info.mem = entry.value;
        } else if (operand.type === "imm") {
            entry.value = operand.value >>> 0;
        } else {
            entry.value = String(operand.value);
        }
        info.operands.push(entry);
    }
    return info;
}

function computeEA(mem, context, nextAddress) {
    let ea = ptr(0);
    if (mem.base === "rip" || mem.base === "eip") {
        ea = ea.add(ptr(nextAddress));
    } else if (mem.base !== undefined) {
        ea = ea.add(context[mem.base]);
    }
    if (mem.index !== undefined) {
        ea = ea.add(context[mem.index].mul(mem.scale || 1));
    }
    if (mem.disp !== undefined) {
        ea = ea.add(mem.disp);
    }
    return ea;
}

/* Called for every 1-byte memory store in the main module. */
function recordCandidate(info, context) {
    stats.byteWrites++;
    if (!plan.licMapped) {
        return;
    }
    let tid = null;
    try {
        tid = Process.getCurrentThreadId();
    } catch (e) {
        return;
    }
    if (plan.mainThread !== null && tid !== plan.mainThread) {
        return;
    }
    let byte = null;
    try {
        byte = writtenByte(info, context);
    } catch (e) {
        return;
    }
    if (byte !== plan.head[0]) {
        return;
    }
    const ea = computeEA(info.mem, context, info.next);
    if (plan.copySet[ea.toString()] === undefined) {
        plan.copySet[ea.toString()] = info.address;
        stats.candidates++;
        if (stats.candidates <= 8) {
            emit({
                spike: "candidate",
                n: stats.candidates,
                ea: ea.toString(),
                byte: byte,
                insn: info.address + " " + info.mnemonic + " " + info.opStr
            });
        }
    }
}

function install(iterator) {
    let insn;
    while ((insn = iterator.next()) !== null) {
        stats.instructions++;
        const address = insn.address;
        if (address.compare(plan.moduleEnd) >= 0 ||
            address.compare(plan.moduleBase) < 0) {
            stats.outside++;
            iterator.keep();
            continue;
        }
        stats.inside++;
        /* 1-byte memory destination = a byte store (or read-modify-write). */
        const first = insn.operands.length > 0 ? insn.operands[0] : null;
        if (first !== null && first.type === "mem" && first.size === 1) {
            const info = snapshot(insn);
            stats.byteStoresPlanned++;
            iterator.putCallout(function (context) {
                try {
                    recordCandidate(info, context);
                } catch (e) {
                    /* never let a callout kill the trace */
                }
            });
        }

        /* Stage 1 instrumentation. It is installed unconditionally and gated
         * inside the callout: adding it only after Stage 0 finds lic_copy
         * cannot work, because Stalker has already compiled (and cached) the
         * blocks that follow, and re-following from inside the hook that
         * detects lic_copy kills the process. Gating costs one property
         * compare per callout.
         *
         * Every memory read is instrumented, whatever its size: the license
         * copy is read byte-wise inside mp_read_unsigned_bin, so a
         * size filter would miss the very read sub-stage 1 waits for. */
        try {
        if (insn.mnemonic !== "lea") {
            let readOperand = null;
            for (let i = 0; i < insn.operands.length; i++) {
                const operand = insn.operands[i];
                if (operand.type !== "mem") {
                    continue;
                }
                /* operands[0] of a plain mov is a pure write */
                if (i === 0 && insn.mnemonic === "mov") {
                    continue;
                }
                readOperand = i;
                break;
            }
            if (readOperand !== null) {
                const info = snapshot(insn);
                info.readIndex = readOperand;
                stats.readCalloutsPlanned++;
                iterator.putCallout(function (context) {
                    try {
                        if (plan.stage1.active) {
                            stage1ReadCallout(info, context);
                        }
                    } catch (e) { }
                });
            }
        }
        if (insn.mnemonic === "call") {
            /* Direct E8 call: read the opcode and the rel32 straight from the
             * code (the instruction snapshot does not carry raw bytes). */
            let directCall = null;
            try {
                if (Memory.readU8(insn.address) === 0xE8) {
                    const rel = Memory.readS32(insn.address.add(1));
                    directCall = insn.address.add(5 + rel).toString();
                }
            } catch (e) {
                directCall = null;
            }
            if (directCall !== null) {
                const info = snapshot(insn);
                info.callDest = directCall;
                stats.callCalloutsPlanned++;
                iterator.putCallout(function (context) {
                    try {
                        if (plan.stage1.active && plan.stage1.sub === 4) {
                            stage1CallCallout(info, context);
                        }
                    } catch (e) { }
                });
            }
        }
        } catch (e) {
            stats.instrumentationErrors++;
        }
        iterator.keep();
    }
}

/* ---------------------------------------------------------------- Windows */

function installWindowsHooks() {
    const ntdll = "ntdll.dll";
    const kernel32 = "kernel32.dll";

    plan.redirectBuffer = Memory.allocUtf16String(plan.ntPath);
    const nameOffset = PTR_SIZE === 8 ? 0x10 : 0x8;
    const bufferOffset = PTR_SIZE === 8 ? 0x8 : 0x4;
    /* RootDirectory is the second field of OBJECT_ATTRIBUTES. Our replacement
     * path is always absolute (\??\...), and the object manager rejects an
     * absolute ObjectName combined with a non-NULL RootDirectory with
     * STATUS_INVALID_PARAMETER (CreateFile -> error 87). That is exactly what
     * happens when the target opens a *relative* "regkey.dat": kernel32 sets
     * RootDirectory to the current directory handle. Zero it. */
    const rootOffset = PTR_SIZE === 8 ? 0x8 : 0x4;

    const createFileHook = function (callSite) {
        return function (args) {
            const objectAttributes = args[2];
            if (objectAttributes.isNull()) {
                return;
            }
            const objectName = objectAttributes.add(nameOffset).readPointer();
            if (objectName.isNull()) {
                return;
            }
            const length = objectName.readU16();
            const buffer = objectName.add(bufferOffset).readPointer();
            if (buffer.isNull() || length === 0) {
                return;
            }
            let path = "";
            try {
                path = buffer.readUtf16String(length / 2);
            } catch (e) {
                return;
            }
            stats.fileOpens++;
            /* Record what the target actually opens: with a real sample the
             * first question is whether it looks for a license file at all,
             * and under which name. */
            if (report.openedPaths.length < 80 &&
                report.openedPaths.indexOf(path) < 0) {
                report.openedPaths.push(path);
            }
            if (path.slice(-10).toLowerCase() !== "regkey.dat") {
                return;
            }
            report.originalLicensePath = path;
            plan.mainThread = Process.getCurrentThreadId();
            report.mainThread = plan.mainThread;
            report.redirectedVia = callSite;
            stats.redirects++;
            const previousRoot = objectAttributes.add(rootOffset)
                .readPointer();
            objectName.writeU16(plan.ntPath.length * 2);
            objectName.add(2).writeU16((plan.ntPath.length + 1) * 2);
            objectName.add(bufferOffset).writePointer(plan.redirectBuffer);
            if (!previousRoot.isNull()) {
                objectAttributes.add(rootOffset).writePointer(ptr(0));
                report.clearedRootDirectory =
                    (report.clearedRootDirectory || 0) + 1;
            }
            emit({
                spike: "redirect",
                via: callSite,
                original: path,
                replacement: plan.ntPath,
                thread: plan.mainThread
            });
        };
    };

    for (const exportName of ["NtCreateFile", "ZwCreateFile"]) {
        const address = Module.findExportByName(ntdll, exportName);
        if (address === null) {
            report.errors.push(exportName + " not found");
            continue;
        }
        plan.hooks.push(Interceptor.attach(address,
            { onEnter: createFileHook(exportName) }));
    }

    const mapView = Module.findExportByName(kernel32, "MapViewOfFile");
    if (mapView !== null) {
        plan.hooks.push(Interceptor.attach(mapView, {
            onLeave: function (retval) {
                stats.maps++;
                if (headMatches(retval)) {
                    plan.licMapped = true;
                    plan.mapAddress = retval.toString();
                    report.licenseMappedTo = retval.toString();
                    emit({ spike: "lic_mapped", addr: retval.toString() });
                    if (!plan.tracing) {
                        /* startTracing is an rpc export; call it through the
                         * same code path by hand to avoid re-entrancy. */
                        plan.tracing = true;
                        followStart = Date.now();
                        for (const thread of Process.enumerateThreads()) {
                            try {
                                Stalker.follow(thread.id,
                                               { transform: install });
                                plan.followed.push(thread.id);
                            } catch (e) {
                                report.errors.push("follow " + thread.id +
                                                   ": " + String(e));
                            }
                        }
                        report.followedThreads = plan.followed;
                        emit({ spike: "tracing_started_at_map",
                               threads: plan.followed.length });
                    }
                }
            }
        }));
    } else {
        report.errors.push("MapViewOfFile not found");
    }

    const unmapView = Module.findExportByName(kernel32, "UnmapViewOfFile");
    if (unmapView !== null) {
        plan.hooks.push(Interceptor.attach(unmapView, {
            onEnter: function (args) {
                if (!plan.licMapped) {
                    return;
                }
                if (!headMatches(args[0])) {
                    return;
                }
                plan.licMapped = false;
                resolveCopy(args[0].toString(), "UnmapViewOfFile");
            }
        }));
    } else {
        report.errors.push("UnmapViewOfFile not found");
    }
}

/* ------------------------------------------------------------------ Linux */

function installLinuxHooks() {
    const libc = "libc.so.6";
    const mmapAddr = Module.findExportByName(libc, "mmap") ||
        Module.findExportByName(null, "mmap");
    const munmapAddr = Module.findExportByName(libc, "munmap") ||
        Module.findExportByName(null, "munmap");
    if (mmapAddr !== null) {
        plan.hooks.push(Interceptor.attach(mmapAddr, {
            onLeave: function (retval) {
                stats.maps++;
                if (headMatches(retval)) {
                    plan.licMapped = true;
                    plan.mapAddress = retval.toString();
                    report.licenseMappedTo = retval.toString();
                    emit({ spike: "lic_mapped", addr: retval.toString() });
                    if (!plan.tracing) {
                        /* startTracing is an rpc export; call it through the
                         * same code path by hand to avoid re-entrancy. */
                        plan.tracing = true;
                        followStart = Date.now();
                        for (const thread of Process.enumerateThreads()) {
                            try {
                                Stalker.follow(thread.id,
                                               { transform: install });
                                plan.followed.push(thread.id);
                            } catch (e) {
                                report.errors.push("follow " + thread.id +
                                                   ": " + String(e));
                            }
                        }
                        report.followedThreads = plan.followed;
                        emit({ spike: "tracing_started_at_map",
                               threads: plan.followed.length });
                    }
                }
            }
        }));
    } else {
        report.errors.push("mmap not found");
    }
    if (munmapAddr !== null) {
        plan.hooks.push(Interceptor.attach(munmapAddr, {
            onEnter: function (args) {
                if (!plan.licMapped) {
                    return;
                }
                if (!headMatches(args[0])) {
                    return;
                }
                plan.licMapped = false;
                resolveCopy(args[0].toString(), "munmap");
            }
        }));
    } else {
        report.errors.push("munmap not found");
    }
}

/* Search the recorded candidates for the address that now holds the license
 * head — the same test the PIN tool runs after the unmap. */
function resolveCopy(unmappedAddress, via) {
    const candidates = Object.keys(plan.copySet);
    report.candidates = candidates.length;
    report.unmapped = unmappedAddress;
    for (const candidate of candidates) {
        const address = ptr(candidate);
        if (headMatches(address)) {
            plan.licCopy = candidate;
            report.licCopy = candidate;
            report.licCopyFirstBytes = hex(
                new Uint8Array(address.readByteArray(HEAD_LEN)));
            emit({
                spike: "lic_copy",
                via: via,
                addr: candidate,
                candidates: candidates.length,
                bytes: report.licCopyFirstBytes
            });
            startStage1(candidate);
            return;
        }
    }
    report.licCopy = null;
    emit({
        spike: "lic_copy_missing",
        via: via,
        candidates: candidates.length
    });
}

/* ======================================================================
 * Stage 1 -- RSA bypass (port of wl-extract/staging/stage1.cpp)
 *
 * Sub-stage chain, all driven from read/call callouts:
 *   1  first read whose EA == lic_copy (= inside mp_read_unsigned_bin)
 *      -> ret_to_rsaexptmod = [esp+8]
 *   2  execution reaches that address (back inside rsa_exptmod)
 *      -> dec_lic = [esp+0x8c], key_tmp_ref = ebp+0x1c
 *   3  the second read at key_tmp_ref -> the next call is mp_exptmod
 *   4  first direct (E8) call -> its destination is mp_exptmod
 *   5  at mp_exptmod's entry: swap the key pointers for the first
 *      dec_sections calls (decrypt), then for the verify call
 *   6  done: dec_lic is the RSA-decrypted license buffer (Stage 2 input)
 *
 * x86 reads the arguments off the stack; x64 keeps them in registers, so
 * both slot kinds are supported and the mapping is configurable.
 * ====================================================================== */

function stage1Log(event, detail) {
    emit({ spike: "stage1", event: event, detail: detail });
}

/* libtommath mp_int on the target: { int used; int alloc; int sign; mp_digit *dp; } */
function buildMpInt(hexDigits, digitCount) {
    const bytes = [];
    for (let i = 0; i < digitCount * 4; i += 2) {
        bytes.push(parseInt(hexDigits.substr(i * 2, 2), 16));
    }
    const digits = Memory.alloc(digitCount * 4);
    for (let i = 0; i < bytes.length; i++) {
        digits.add(i).writeU8(bytes[i]);
    }
    const mp = Memory.alloc(16);
    mp.writeS32(digitCount);          /* used  */
    mp.writeS32(digitCount);          /* alloc */
    mp.writeS32(0);                   /* sign = MP_ZPOS */
    mp.add(12).writePointer(digits);  /* dp */
    return { struct: mp, digits: digits };
}

function stage1KeyMaterial() {
    const stage1 = plan.stage1;
    if (stage1.mpInts !== null || plan.rsaKeys === null) {
        return stage1.mpInts;
    }
    stage1.mpInts = {
        key1: {
            exp: buildMpInt(plan.rsaKeys.exp1, plan.rsaKeys.exp1Len),
            mod: buildMpInt(plan.rsaKeys.mod1, plan.rsaKeys.mod1Len)
        },
        key2: {
            exp: buildMpInt(plan.rsaKeys.exp2, plan.rsaKeys.exp2Len),
            mod: buildMpInt(plan.rsaKeys.mod2, plan.rsaKeys.mod2Len)
        }
    };
    stage1Log("keys-materialised",
        "key1 exp=" + stage1.mpInts.key1.exp.struct +
        " mod=" + stage1.mpInts.key1.mod.struct +
        " key2 exp=" + stage1.mpInts.key2.exp.struct +
        " mod=" + stage1.mpInts.key2.mod.struct);
    return stage1.mpInts;
}

function slotRead(context, slot) {
    if (slot.kind === "reg") {
        return context[slot.name];
    }
    return context[SP_REG].add(slot.offset).readPointer();
}

function slotWrite(context, slot, value) {
    if (slot.kind === "reg") {
        context[slot.name] = value;
        return;
    }
    context[SP_REG].add(slot.offset).writePointer(value);
}

/* Describe an mp_int the target passed in, so the first run tells us which
 * argument is the exponent and which is the modulus. */
function describeMpInt(pointer) {
    if (pointer.isNull()) {
        return "null";
    }
    try {
        const used = pointer.readS32();
        const alloc = pointer.readS32();
        const sign = pointer.readS32();
        const dp = pointer.add(12).readPointer();
        const digits = [];
        for (let i = 0; i < Math.min(used, 4); i++) {
            digits.push(dp.add(i * 4).readU32().toString(16));
        }
        return "{used:" + used + ",alloc:" + alloc + ",sign:" + sign +
            ",dp:" + dp + ",digits:[" + digits.join(",") + "]}";
    } catch (e) {
        return "{unreadable: " + String(e) + "}";
    }
}

function stage1MpExptmodEnter(context) {
    const stage1 = plan.stage1;
    stage1.callCount++;
    const slots = plan.stage1KeySlots;
    const observed = [];
    for (let i = 0; i < slots.length; i++) {
        observed.push("arg" + i + "(" + (slots[i].kind === "reg"
            ? slots[i].name : "esp+" + slots[i].offset) + ")=" +
            describeMpInt(slotRead(context, slots[i])));
    }
    if (!stage1.firstSwapLogged) {
        stage1.firstSwapLogged = true;
        stage1Log("mp_exptmod-enter", "call#" + stage1.callCount +
            " dec_sections=" + stage1.decSections + " | " +
            observed.join(" | "));
    }
    const keys = stage1KeyMaterial();
    if (keys === null) {
        return;
    }
    if (stage1.callCount <= stage1.decSections) {
        slotWrite(context, slots[0], keys.key2.exp.struct);
        slotWrite(context, slots[1], keys.key2.mod.struct);
        stage1Log("swap", "call#" + stage1.callCount + " <- rsa_key_2");
    } else {
        slotWrite(context, slots[0], keys.key1.exp.struct);
        slotWrite(context, slots[1], keys.key1.mod.struct);
        stage1Log("swap", "call#" + stage1.callCount + " <- rsa_key_1");
        stage1.sub = 6;
        report.stage1DecLic = stage1.decLic;
        report.stage1Complete = true;
        stage1Log("complete", "dec_lic=" + stage1.decLic +
            " (RSA-decrypted license buffer, Stage 2 input)");
    }
}

function stage1ReadCallout(info, context) {
    const stage1 = plan.stage1;
    if (!stage1.active) {
        return;
    }
    let ea;
    try {
        ea = computeEA(info.mem, context, info.next);
    } catch (e) {
        return;
    }
    stats.readCalloutsFired++;
    if (stats.readCalloutsFired <= 5) {
        stage1Log("read-callout", "#" + stats.readCalloutsFired + " at " +
            info.address + " ea=" + ea + " (want " + stage1.preRsaBuf + ")");
    }
    if (stage1.sub === 1 && ea.equals(stage1.preRsaBuf)) {
        /* [esp+8] on ia32 = the return address back inside rsa_exptmod */
        const ret = plan.retSlot.kind === "reg"
            ? context[plan.retSlot.name]
            : context[SP_REG].add(plan.retSlot.offset).readPointer();
        stage1.retToRsa = ret.toString();
        stage1.sub = 2;
        stage1Log("sub1-lic-read", "read at " + info.address + " ea=" + ea +
            " -> ret_to_rsaexptmod=" + stage1.retToRsa + " ([esp+8])");
        /* Waiting for execution to reach that address is done with an
         * Interceptor hook: it fires under Stalker, and an every-instruction
         * callout would be far too expensive.
         *
         * The attach MUST be deferred: calling Interceptor.attach (or any
         * other heavy frida API) from inside a Stalker callout deadlocks the
         * process -- it hung a CI job for 16 minutes. setTimeout runs it on
         * frida's own JS thread instead. */
        const retAddress = ret;
        setTimeout(function () {
            try {
                plan.hooks.push(Interceptor.attach(retAddress, {
                    onEnter: function () {
                        try {
                            stage1BackInRsaExptmod(this.context);
                        } catch (e) {
                            stage1Log("sub2-error", String(e));
                        }
                    }
                }));
                stage1Log("sub2-hooked", "waiting for " + stage1.retToRsa);
            } catch (e) {
                stage1Log("sub2-hook-failed", String(e));
            }
        }, 0);
        return;
    }
    if (stage1.sub === 3 && stage1.keyRef !== null &&
        ea.equals(stage1.keyRef)) {
        stage1.keyRefReads++;
        stage1Log("sub3-keyref-read", "#" + stage1.keyRefReads + " at " +
            info.address + " ea=" + ea);
        if (stage1.keyRefReads >= 2) {
            stage1.sub = 4;
            stage1Log("sub4-armed", "next E8 call is mp_exptmod");
        }
    }
}

/* Fired by a callout on every direct (E8) call while sub-stage 4 is armed. */
function stage1CallCallout(info, context) {
    const stage1 = plan.stage1;
    if (!stage1.active || stage1.sub !== 4) {
        return;
    }
    stage1.mpExptmod = info.callDest;
    stage1.lastCall = info.address + " -> " + info.callDest;
    stage1.sub = 5;
    stage1Log("sub4-found-mp_exptmod", "call at " + info.address +
        " -> " + info.callDest);
    const destination = ptr(info.callDest);
    setTimeout(function () {
        try {
            plan.hooks.push(Interceptor.attach(destination, {
                onEnter: function () {
                    try {
                        stage1MpExptmodEnter(this.context);
                    } catch (e) {
                        stage1Log("mp_exptmod-error", String(e));
                    }
                }
            }));
            stage1Log("mp_exptmod-hooked", "Interceptor attached at " +
                info.callDest);
        } catch (e) {
            stage1Log("mp_exptmod-hook-failed", String(e));
        }
    }, 0);
}

/* Sub-stage 2: execution is back inside rsa_exptmod. */
function stage1BackInRsaExptmod(context) {
    const stage1 = plan.stage1;
    if (!stage1.active || stage1.sub !== 2) {
        return;
    }
    stage1.decLic = context[SP_REG].add(plan.decLicSlot.offset)
        .readPointer().toString();
    stage1.keyRef = context[BP_REG].add(plan.keyRefOffset);
    stage1.sub = 3;
    stage1Log("sub2-back-in-rsaexptmod", "dec_lic=" + stage1.decLic +
        " ([esp+" + plan.decLicSlot.offset.toString(16) +
        "]) key_tmp_ref=" + stage1.keyRef + " (ebp+" +
        plan.keyRefOffset.toString(16) + ")");
}

function startStage1(licCopy) {
    const stage1 = plan.stage1;
    stage1.active = true;
    stage1.sub = 1;
    stage1.preRsaBuf = ptr(licCopy);
    stage1.decSections = Math.floor(plan.licSize / 0x80);
    stage1Log("start", "lic_copy=" + licCopy + " lic_size=" + plan.licSize +
        " dec_sections=" + stage1.decSections);
}

rpc.exports = {
    setup: function (options) {
        const headBytes = [];
        for (let i = 0; i < HEAD_LEN; i++) {
            headBytes.push(parseInt(options.headHex.substr(i * 2, 2), 16));
        }
        plan = {
            head: headBytes,
            ntPath: options.ntPath || "",
            licSize: options.licSize || 0,
            /* RSA public keys from the wl-lic output (regkey.rsa), as hex
             * digit arrays -- Stage 1 swaps the program's embedded key
             * pointers for these so our license verifies. */
            rsaKeys: options.rsaKeys || null,
            stage1: {
                active: false, sub: 0,
                preRsaBuf: null, retToRsa: null, decLic: null,
                keyRef: null, keyRefReads: 0,
                mpExptmod: null, callCount: 0, decSections: 0,
                mpInts: null, firstSwapLogged: false, lastCall: null
            },
            licMapped: false,
            licCopy: null,
            copySet: {},
            mainThread: null,
            moduleBase: null,
            moduleEnd: null,
            hooks: [],
            followed: [],
            tracing: false,
            /* x86 reads the RSA arguments off the stack; x64 keeps them in
             * registers (mp_exptmod(G, X, P, Y): X = exponent, P = modulus,
             * i.e. the 2nd and 3rd arguments). */
            retSlot: IS_IA32 ? { kind: "stack", offset: 0x8 }
                : { kind: "reg", name: "r8" },
            decLicSlot: { kind: "stack", offset: 0x8c },
            keyRefOffset: 0x1c,
            stage1KeySlots: IS_IA32
                ? [{ kind: "stack", offset: 0x8 },
                   { kind: "stack", offset: 0xc }]
                : [{ kind: "reg", name: "rdx" },
                   { kind: "reg", name: "r8" }]
        };
        report = {
            platform: Process.platform,
            arch: Process.arch,
            pointerSize: PTR_SIZE,
            errors: [],
            licenseFile: options.licenseFile || "",
            openedPaths: []
        };
        stats = {
            instructions: 0, inside: 0, outside: 0, byteStoresPlanned: 0,
            byteWrites: 0, candidates: 0, maps: 0, fileOpens: 0,
            redirects: 0, elapsedMs: 0, readCalloutsPlanned: 0,
            callCalloutsPlanned: 0, insCalloutsPlanned: 0,
            instrumentationErrors: 0, readCalloutsFired: 0
        };

        const modules = Process.enumerateModules();
        const main = modules[0];
        plan.moduleBase = main.base;
        plan.moduleEnd = main.base.add(main.size);
        report.mainModule = main.name + " " + main.base;

        if (IS_WINDOWS) {
            installWindowsHooks();
        } else {
            installLinuxHooks();
        }

        /* Everything outside the main module runs natively: the protection's
         * copy loop lives in the protected image. */
        let excluded = 0;
        for (const module of modules) {
            if (module.name === main.name) {
                continue;
            }
            try {
                Stalker.exclude({ base: module.base, size: module.size });
                excluded++;
            } catch (e) {
                report.errors.push("exclude " + module.name + ": " +
                    String(e));
            }
        }
        report.excludedModules = excluded;

        report.followedThreads = plan.followed;
        if (options.retSlot) { plan.retSlot = options.retSlot; }
        if (options.decLicSlot) { plan.decLicSlot = options.decLicSlot; }
        if (options.keyRefOffset !== undefined) {
            plan.keyRefOffset = options.keyRefOffset;
        }
        if (options.stage1KeySlots) {
            plan.stage1KeySlots = options.stage1KeySlots;
        }
        log("stage0 hooks armed (license head " + options.headHex + ")");
        return report;
    },

    /* Stalker has to start AFTER the process is resumed: following a thread
     * that the spawner has stopped does not take effect (the run then traces
     * nothing at all while the hooks still work). The map hook calls this too
     * so tracing cannot be missed even if the host's call is late. */
    startTracing: function () {
        if (plan.tracing) {
            return { alreadyStarted: true, threads: plan.followed.length };
        }
        plan.tracing = true;
        followStart = Date.now();
        for (const thread of Process.enumerateThreads()) {
            try {
                Stalker.follow(thread.id, { transform: install });
                plan.followed.push(thread.id);
            } catch (e) {
                report.errors.push("follow " + thread.id + ": " + String(e));
            }
        }
        report.followedThreads = plan.followed;
        log("tracing started: " + plan.followed.length + " threads followed");
        return { started: true, threads: plan.followed.length };
    },

    status: function () {
        return {
            redirects: stats.redirects,
            licenseMapped: plan.licMapped,
            mappedTo: report.licenseMappedTo || null,
            candidates: Object.keys(plan.copySet).length,
            licCopy: plan.licCopy,
            byteWrites: stats.byteWrites,
            byteStoresPlanned: stats.byteStoresPlanned,
            originalLicensePath: report.originalLicensePath || null,
            fileOpens: stats.fileOpens,
            openedPaths: report.openedPaths.slice(0, 6),
            stage1Sub: plan.stage1.sub,
            stage1MpExptmod: plan.stage1.mpExptmod,
            stage1DecLic: plan.stage1.decLic,
            stage1Calls: plan.stage1.callCount
        };
    },

    finish: function () {
        stats.elapsedMs = Date.now() - followStart;
        report.stats = stats;
        report.candidates = Object.keys(plan.copySet);
        try {
            for (const id of plan.followed) {
                Stalker.unfollow(id);
            }
            Stalker.flush();
            Stalker.garbageCollect();
            report.unfollowed = true;
        } catch (e) {
            report.errors.push("unfollow: " + String(e));
        }
        for (const hook of plan.hooks) {
            try {
                hook.detach();
            } catch (e) {
                /* already gone */
            }
        }
        report.licMapped = plan.licMapped;
        report.stage1 = {
            sub: plan.stage1.sub,
            preRsaBuf: plan.stage1.preRsaBuf
                ? plan.stage1.preRsaBuf.toString() : null,
            retToRsa: plan.stage1.retToRsa,
            decLic: plan.stage1.decLic,
            keyRef: plan.stage1.keyRef ? plan.stage1.keyRef.toString() : null,
            keyRefReads: plan.stage1.keyRefReads,
            mpExptmod: plan.stage1.mpExptmod,
            lastCall: plan.stage1.lastCall,
            callCount: plan.stage1.callCount,
            decSections: plan.stage1.decSections,
            complete: report.stage1Complete === true
        };
        return report;
    }
};
