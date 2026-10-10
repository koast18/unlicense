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

        /* Stage 1 does NOT instrument reads or calls. A callout on every
         * memory read costs ~100x what PIN's native instrumentation costs:
         * measured 500k callouts fired in a few seconds on drchost, which
         * slows the protection's own unpacking so much that the RSA path is
         * minutes away instead of seconds. Sub-stage 1 uses a guard page
         * (exception handler) and sub-stages 3/4 a static call scan, both of
         * which leave the target running at native speed until it touches
         * what we care about. */
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
        disarmGuard();
        stage1.sub = 6;
        report.stage1DecLic = stage1.decLic;
        report.stage1Complete = true;
        stage1Log("complete", "dec_lic=" + stage1.decLic +
            " (RSA-decrypted license buffer, Stage 2 input)");
    }
}


/* Fired by a callout on every direct (E8) call while sub-stage 4 is armed. */

/* Sub-stage 2: execution is back inside rsa_exptmod. The destination buffer
 * for the RSA-decrypted license is an argument of this frame, at a
 * build-specific offset (the PIN original uses [esp+0x8c]); every candidate
 * slot is logged so the right one can be pinned down, and the first heap
 * pointer found is used. */
function stage1BackInRsaExptmod(context) {
    const stage1 = plan.stage1;
    if (!stage1.active || stage1.sub !== 2) {
        return;
    }
    const sp = context[SP_REG];
    const observed = [];
    let chosen = null;
    for (const offset of plan.decLicCandidates) {
        let value = null;
        let writable = false;
        let onStack = false;
        try {
            value = sp.add(offset).readPointer();
            const range = Process.findRangeByAddress(value);
            writable = range !== null && range.protection.indexOf("w") >= 0;
            onStack = value.compare(sp) >= 0 &&
                value.compare(sp.add(0x20000)) < 0;
        } catch (e) {
            /* unreadable slot */
        }
        if (value !== null) {
            observed.push("[sp+" + offset.toString(16) + "]=" + value +
                (writable ? " w" : "") + (onStack ? " stack" : ""));
            if (chosen === null && writable && !onStack) {
                chosen = value;
            }
        }
    }
    stage1.decLic = chosen !== null ? chosen.toString() : null;
    stage1.sub = 3;
    stage1Log("sub2-back-in-rsaexptmod", "pc=" + context[PC_REG] +
        " dec_lic=" + stage1.decLic + " frame: " + observed.join(" "));

    /* Sub-stages 3-5 in one step: scan this function's code for direct calls
     * and hook each destination; the RSA call is recognised by its arguments
     * being libtommath mp_ints of the expected digit counts. */
    const destinations = stage1ScanCalls(ptr(stage1.retToRsa));
    stage1Log("sub3-call-candidates", destinations.length +
        " direct calls in the function: " +
        destinations.slice(0, 12).map(function (address) {
            return address.toString();
        }).join(" "));
    for (const destination of destinations) {
        setTimeout(function () {
            try {
                plan.hooks.push(Interceptor.attach(destination, {
                    onEnter: function () {
                        try {
                            stage1CallCandidate(this.context, destination);
                        } catch (e) {
                            stage1Log("candidate-error", String(e));
                        }
                    }
                }));
            } catch (e) {
                stage1Log("candidate-hook-failed", String(e));
            }
        }, 0);
    }
}

/* Parse forward from `fromAddress`, collecting the destinations of direct
 * (E8) calls -- the PIN original takes the next executed call; scanning and
 * then fingerprinting the arguments is both cheaper and less fragile. */
function stage1ScanCalls(fromAddress) {
    const destinations = [];
    let address = fromAddress;
    for (let i = 0; i < 4000; i++) {
        let insn;
        try {
            insn = Instruction.parse(address);
        } catch (e) {
            break;
        }
        if (insn.mnemonic === "ret" || insn.mnemonic === "retf") {
            break;
        }
        if (insn.mnemonic === "call") {
            try {
                if (Memory.readU8(address) === 0xE8) {
                    const rel = Memory.readS32(address.add(1));
                    destinations.push(address.add(5 + rel));
                }
            } catch (e) {
                /* indirect or unreadable */
            }
        }
        address = insn.next;
    }
    return destinations;
}

/* Does this pointer look like a libtommath mp_int whose digit count matches
 * one of the RSA key components we are about to swap in? */
function looksLikeKeyMpInt(pointer) {
    if (pointer.isNull()) {
        return null;
    }
    const keys = plan.rsaKeys;
    if (keys === null) {
        return null;
    }
    const expected = [keys.mod1Len, keys.exp1Len, keys.mod2Len, keys.exp2Len];
    try {
        const used = pointer.readS32();
        const alloc = pointer.readS32();
        const sign = pointer.readS32();
        const dp = pointer.add(12).readPointer();
        if (used <= 0 || alloc < used || sign < 0 || sign > 1 ||
            dp.isNull()) {
            return null;
        }
        if (expected.indexOf(used) < 0) {
            return null;
        }
        /* the digits must be readable */
        dp.add((used - 1) * 4).readU32();
        return { used: used, alloc: alloc, sign: sign, dp: dp };
    } catch (e) {
        return null;
    }
}

/* Called at the entry of every direct call inside rsa_exptmod: the RSA call
 * is the one whose arguments are the key mp_ints. */
function stage1CallCandidate(context, destination) {
    const stage1 = plan.stage1;
    if (!stage1.active || stage1.sub < 3 || stage1.sub === 6) {
        return;
    }
    const slots = plan.stage1KeySlots;
    const described = [];
    let matches = 0;
    const values = [];
    for (let i = 0; i < slots.length; i++) {
        const value = slotRead(context, slots[i]);
        values.push(value);
        const shape = looksLikeKeyMpInt(value);
        described.push("arg" + i + "=" + value + " " +
            (shape === null ? describeMpInt(value) : "MP_INT" +
                JSON.stringify(shape.used)));
        if (shape !== null) {
            matches++;
        }
    }
    if (matches === 0) {
        return;
    }
    stage1.callCount++;
    if (stage1.callCount === 1) {
        stage1.mpExptmod = destination.toString();
        stage1.sub = 5;
        stage1Log("sub4-found-mp_exptmod", "call target " + destination +
            " matched " + matches + " key-shaped args: " +
            described.join(" | "));
    } else {
        stage1Log("rsa-call-again", "call#" + stage1.callCount + " at " +
            destination + " " + described.join(" | "));
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
        disarmGuard();
        stage1.sub = 6;
        report.stage1DecLic = stage1.decLic;
        report.stage1Complete = true;
        stage1Log("complete", "dec_lic=" + stage1.decLic +
            " (RSA-decrypted license buffer, Stage 2 input)");
    }
}

/* Candidate "return address back in rsa_exptmod" slots. The PIN original
 * hardcodes [esp+8]; on x64 the frame layout differs, so several slots are
 * collected and the first one that holds a non-system address is used (and
 * reported, so the offsets can be pinned down). */
/* True for Windows' own DLLs. The protection's code lives either in the main
 * module's image or in memory it allocated for itself (findModuleByAddress
 * returns null for the latter); neither is a system module. Filtering on the
 * module *path* rather than on the main module's name keeps both. */
function stage1IsSystemModule(module) {
    if (module === null || module === undefined) {
        return false;
    }
    const path = (module.path || "").toLowerCase();
    return path.indexOf("\\windows\\") !== -1;
}

function stage1ReturnCandidates(context) {
    const slots = [];
    const sp = context[SP_REG];
    for (const offset of plan.retCandidates) {
        try {
            const value = sp.add(offset).readPointer();
            const module = Process.findModuleByAddress(value);
            slots.push({
                offset: offset,
                value: value.toString(),
                inModule: !stage1IsSystemModule(module)
            });
        } catch (e) {
            slots.push({ offset: offset, value: "unreadable" });
        }
    }
    return slots;
}

/* ---------------------------------------------------------------------
 * Guard-page plumbing.
 *
 * The PIN original sees every read through INS callouts. Frida's closest
 * equivalent for "tell me when this page is touched" is a real Windows
 * guard page: PAGE_READWRITE | PAGE_GUARD raises a one-shot
 * STATUS_GUARD_PAGE_VIOLATION (0x80000001) on the first access and the OS
 * then clears the guard bit, so the instruction simply retries. That is
 * *not* the same as Memory.protect(..., "---"): a no-access page raises a
 * hard ACCESS_VIOLATION (0xC0000005), which the target's own SEH treats as
 * a crash. The license copy lives on the heap, so the allocator or the
 * program writing anywhere else in that page would kill the process --
 * which is exactly the 2.7s exit this replaces.
 *
 * The guard is armed once and never re-armed: the OS clears the guard bit on
 * the first violation so the faulting instruction retries and completes. Re-
 * arming inside the handler would make that retry fault again on the same
 * instruction and spin the thread forever (observed as the status RPC timing
 * out while the process stayed alive). The first read anywhere in the page is
 * taken as the landmark instead.
 * ------------------------------------------------------------------- */
const PAGE_READWRITE = 0x04;
const PAGE_GUARD = 0x100;

/* Cap on deferred re-arms. A page that is touched continuously would
 * otherwise re-arm forever; after this many attempts we give up and say so
 * rather than slowing the target to a crawl. */
const MAX_REARMS = 20000;

let virtualProtect = null;
function getVirtualProtect() {
    if (virtualProtect === null) {
        const addr = Module.getExportByName("kernel32.dll",
            "VirtualProtect");
        virtualProtect = new NativeFunction(addr, "int",
            ["pointer", "size_t", "uint32", "pointer"]);
    }
    return virtualProtect;
}

/* Re-arm the guard AFTER the faulting instruction has retried and completed.
 *
 * Arming from inside the exception handler is fatal: the OS clears the guard
 * bit when it raises STATUS_GUARD_PAGE_VIOLATION so the faulting instruction
 * can retry, and putting the guard back before that retry makes the retry
 * fault on the same instruction again -- the thread then spins inside the
 * handler forever (observed as the status RPC timing out while the process
 * stayed alive). Deferring to the JS thread lets the retry finish first.
 */
function scheduleRearm() {
    const stage1 = plan.stage1;
    if (!stage1.active || stage1.sub !== 1 || stage1.rearmPending) {
        return;
    }
    if (stage1.rearms >= MAX_REARMS) {
        if (!stage1.rearmCapped) {
            stage1.rearmCapped = true;
            stage1Log("rearm-capped", "gave up after " + stage1.rearms +
                " re-arms; the page is touched continuously");
        }
        return;
    }
    stage1.rearmPending = true;
    setTimeout(function () {
        stage1.rearmPending = false;
        if (plan.stage1.active && plan.stage1.sub === 1) {
            plan.stage1.rearms++;
            armGuard();
        }
    }, 0);
}

function armGuard() {
    const stage1 = plan.stage1;
    if (stage1.guardStart === null || stage1.guardLength <= 0) {
        stage1.guardArmed = false;
        return false;
    }
    const old = Memory.alloc(4);
    const ok = getVirtualProtect()(stage1.guardStart,
        stage1.guardLength, PAGE_READWRITE | PAGE_GUARD, old);
    stage1.guardArmed = ok !== 0;
    return stage1.guardArmed;
}

function disarmGuard() {
    const stage1 = plan.stage1;
    if (stage1.guardStart === null || stage1.guardLength <= 0) {
        return;
    }
    const old = Memory.alloc(4);
    getVirtualProtect()(stage1.guardStart, stage1.guardLength,
        PAGE_READWRITE, old);
    stage1.guardArmed = false;
}

function stage1OnLicensePageAccess(details) {
    const stage1 = plan.stage1;
    if (!stage1.active || stage1.sub !== 1) {
        return false;
    }
    const memory = details.memory || null;
    let address = null;
    let operation = "read";
    if (memory !== null) {
        address = memory.address;
        operation = memory.operation || "read";
    }
    /* A guard-page violation does not always carry the memory descriptor;
     * the faulting address is still on the exception record. */
    if ((address === null || address === undefined) &&
        details.address !== undefined && details.address !== null) {
        address = details.address;
    }
    if (address === null || address === undefined) {
        return false;
    }
    /* Not our page at all: let the exception go to the target. */
    if (stage1.guardStart === null ||
        address.compare(stage1.guardStart) < 0 ||
        address.compare(stage1.guardStart.add(stage1.guardLength)) >= 0) {
        return false;
    }
    /* Guard pages are page-granular, so unrelated objects sharing the page
     * fault too. Count them: a runaway count means the guard strategy needs
     * rethinking. */
    stage1.guardHits = (stage1.guardHits || 0) + 1;
    if (stage1.guardHits <= 8) {
        stage1Log("guard-hit", "#" + stage1.guardHits + " op=" + operation +
            " addr=" + address + " lic_copy=" + stage1.preRsaBuf);
    }
    /* The first READ in the guarded page that comes from the main module is
     * the landmark.
     *
     * Deliberately do NOT re-arm synchronously. The OS cleared the guard bit
     * on this violation, so the faulting instruction retries and completes.
     * Re-arming here would make that retry fault again on the very same
     * instruction and spin the thread forever -- observed as the status RPC
     * timing out while the process stayed alive. Collateral reads are
     * skipped with a deferred re-arm instead (scheduleRearm).
     *
     * Requiring the address to be inside [lic_copy, lic_copy + lic_size) was
     * wrong: that is only the file image, while the program's license
     * structure spans the whole page (the byte-store candidates land at
     * 0x608b80, 0x608bb7 and 0x608d30 for a 465-byte license).
     */
    if (operation !== "read") {
        return true;
    }
    /* The guard bit is already consumed by this violation, so the instruction
     * will retry and succeed. If the exception record carries no context we
     * cannot read the pc; let the access through rather than returning false,
     * which would hand a guard-page violation to the target's own SEH and
     * kill the process. */
    const ctx = details.context || null;
    if (ctx === null) {
        return true;
    }
    const pc = ctx[PC_REG];
    /* Skip only reads issued from a Windows system module. Those are heap
     * bookkeeping on the same page (the previous run showed pc=0x7ffd3ddde6cb
     * in ntdll.dll reading the license page twice). Everything else counts:
     * WinLicense's unpacked protection code does not reliably live inside the
     * main module's image -- it is frequently in memory the protection
     * allocated for itself, which findModuleByAddress reports as null. Gating
     * on the main module discarded exactly the read this stage hunts for. */
    const from = Process.findModuleByAddress(pc);
    if (stage1IsSystemModule(from)) {
        stage1.collateralReads = (stage1.collateralReads || 0) + 1;
        if (stage1.collateralReads <= 5) {
            stage1Log("sub1-collateral-read", "pc=" + pc + " (" +
                from.name + ") addr=" + address);
        }
        /* Skip it and keep watching: re-arm once the retry has completed. */
        scheduleRearm();
        return true;
    }
    if (stage1.guardHits <= 8) {
        stage1Log("sub1-landmark-module", "pc=" + pc + " in " +
            (from === null ? "<private>" : from.name));
    }
    return stage1TakeLandmark(ctx, "op=" + operation + " addr=" + address);
}

/* Sub-stage 1 landmark, shared by both landmark mechanisms.
 *
 * The guard page knows the accessed address; a hardware breakpoint does not
 * (Frida exposes no Dr6), but both know the pc and the stack. Everything
 * after the landmark is identical, so it lives here.
 */
function stage1TakeLandmark(context, label) {
    const stage1 = plan.stage1;
    const candidates = stage1ReturnCandidates(context);
    stage1.retCandidates = candidates;
    stage1Log("sub1-lic-page-access", label + " pc=" + context[PC_REG] + " " +
        candidates.map(function (candidate) {
            return "[sp+" + candidate.offset.toString(16) + "]=" +
                candidate.value + (candidate.inModule ? " (code)" : "");
        }).join(" "));
    /* The guard bit is already cleared by the OS, so the instruction will
     * succeed on retry; no re-protect is needed. */
    stage1.guardArmed = false;
    /* Hook every stack slot that holds a code address inside the module:
     * the first one to be reached is the return into rsa_exptmod, and
     * logging which slot it was pins the offset down for later runs. */
    const usable = candidates.filter(function (candidate) {
        return candidate.inModule;
    });
    if (usable.length === 0) {
        stage1Log("sub1-no-code-return-candidate", "logged candidates above");
        /* No stack slot held a code address, so there is nothing to hook.
         * Report it rather than re-arming, which would spin the thread. */
        report.stage1NoReturnCandidate = true;
        return true;
    }
    stage1.sub = 2;
    stage1.retCandidatesInModule = usable.map(function (candidate) {
        return candidate.offset.toString(16) + "=" + candidate.value;
    });
    for (const candidate of usable) {
        const address = ptr(candidate.value);
        const offset = candidate.offset;
        setTimeout(function () {
            try {
                plan.hooks.push(Interceptor.attach(address, {
                    onEnter: function () {
                        try {
                            if (plan.stage1.sub !== 2) {
                                return;
                            }
                            plan.stage1.retSlotOffset = offset;
                            plan.stage1.retToRsa = address.toString();
                            stage1BackInRsaExptmod(this.context);
                        } catch (e) {
                            stage1Log("sub2-error", String(e));
                        }
                    }
                }));
                stage1Log("sub2-hooked", "candidate [sp+" +
                    offset.toString(16) + "] = " + address);
            } catch (e) {
                stage1Log("sub2-hook-failed", String(e) + " for " + address);
            }
        }, 0);
    }
    return true;
}

function startStage1(licCopy) {
    const stage1 = plan.stage1;
    stage1.active = true;
    stage1.sub = 1;
    stage1.preRsaBuf = ptr(licCopy);
    stage1.decSections = Math.floor(plan.licSize / 0x80);
    /* Guard the page holding the license copy: the first read of it is
     * sub-stage 1's landmark, and a guard page costs nothing until it is
     * touched. */
    const pageSize = Process.pageSize;
    const start = ptr(licCopy).and(ptr(pageSize - 1).not());
    const span = Math.max(plan.licSize || 0x100, 1);
    const length = Math.ceil((ptr(licCopy).sub(start).toUInt32() + span) /
        pageSize) * pageSize;
    stage1.guardStart = start;
    stage1.guardLength = length;
    try {
        armGuard();
        stage1Log("start", "lic_copy=" + licCopy + " lic_size=" +
            plan.licSize + " dec_sections=" + stage1.decSections +
            " guard=" + start + "+0x" + length.toString(16) +
            " armed=" + stage1.guardArmed);
    } catch (e) {
        stage1Log("guard-failed", String(e) + " -- falling back to " +
            "unguarded detection");
    }
    /* Second, independent landmark mechanism: data breakpoints on the byte
     * store candidates. Exact, so it needs no collateral filtering and no
     * re-arming. Both run at once; whichever sees the license first wins and
     * the other is torn down. */
    try {
        const addresses = Object.keys(plan.copySet).map(function (a) {
            return ptr(a);
        });
        hwBreakInstall(plan, addresses);
    } catch (e) {
        stage1Log("hwbreak-install-failed", String(e));
    }
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
                keyRef: null, keyRefReads: 0, guardStart: null,
                guardLength: 0, guardArmed: false, guardHits: 0,
                collateralReads: 0, rearms: 0, rearmPending: false,
                rearmCapped: false,
                retCandidates: [],
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
            exceptionsSeen: 0,
            /* Hardware-breakpoint landmark (spikes/hwbreak_agent.js). Both
             * mechanisms run at once: whichever sees the license first takes
             * sub-stage 1, and the other is torn down. */
            emit: emit,
            PC_REG: PC_REG,
            hwBreakActive: false,
            hwBreakThreads: [],
            hwBreakHits: 0,
            onHwBreakLandmark: function (context) {
                if (plan.stage1.sub !== 1) {
                    return;
                }
                disarmGuard();
                stage1TakeLandmark(context, "hwbreak");
            },
            /* x86 reads the RSA arguments off the stack; x64 keeps them in
             * registers (mp_exptmod(G, X, P, Y): X = exponent, P = modulus,
             * i.e. the 2nd and 3rd arguments). */
            retSlot: IS_IA32 ? { kind: "stack", offset: 0x8 }
                : { kind: "reg", name: "r8" },
            decLicSlot: { kind: "stack", offset: 0x8c },
            decLicCandidates: [0x8c, 0x90, 0x94, 0xa0, 0xb0],
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
        if (options.retCandidates) {
            plan.retCandidates = options.retCandidates;
        }
        if (options.decLicCandidates) {
            plan.decLicCandidates = options.decLicCandidates;
        }
        /* Candidate stack slots for the return address back into
         * rsa_exptmod: the PIN original uses [esp+8]. */
        plan.retCandidates = options.retCandidates ||
            (IS_IA32 ? [0x0, 0x4, 0x8, 0xc, 0x10, 0x14, 0x18]
                     : [0x0, 0x8, 0x10, 0x18, 0x20, 0x28]);
        plan.mainModuleName = main.name;
        Process.setExceptionHandler(function (details) {
            try {
                /* Log the first few exceptions so a guard-page violation
                 * (0x80000001) is distinguishable from a genuine crash
                 * (0xC0000005) in the run report. */
                if (plan.exceptionsSeen < 6) {
                    plan.exceptionsSeen++;
                    stage1Log("exception", "type=" + details.type +
                        " addr=" + details.address + " mem=" +
                        (details.memory
                            ? (details.memory.operation + "@" +
                               details.memory.address)
                            : "none"));
                }
                if (hwBreakOnException(plan, details)) {
                    return true;
                }
                return stage1OnLicensePageAccess(details);
            } catch (e) {
                stage1Log("exception-handler-error", String(e));
                return false;
            }
        });
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
            stage1GuardHits: plan.stage1.guardHits,
            stage1GuardArmed: plan.stage1.guardArmed,
            stage1CollateralReads: plan.stage1.collateralReads,
            stage1Rearms: plan.stage1.rearms,
            stage1HwBreakActive: plan.hwBreakActive,
            stage1HwBreakHits: plan.hwBreakHits,
            stage1Complete: report.stage1Complete === true,
            stage1MpExptmod: plan.stage1.mpExptmod,
            stage1DecLic: plan.stage1.decLic,
            stage1Calls: plan.stage1.callCount,
            retToRsa: plan.stage1.retToRsa
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
            retSlotOffset: plan.stage1.retSlotOffset,
            retCandidatesInModule: plan.stage1.retCandidatesInModule,
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
