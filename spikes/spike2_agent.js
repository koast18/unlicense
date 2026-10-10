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

rpc.exports = {
    setup: function (options) {
        const headBytes = [];
        for (let i = 0; i < HEAD_LEN; i++) {
            headBytes.push(parseInt(options.headHex.substr(i * 2, 2), 16));
        }
        plan = {
            head: headBytes,
            ntPath: options.ntPath || "",
            licMapped: false,
            licCopy: null,
            copySet: {},
            mainThread: null,
            moduleBase: null,
            moduleEnd: null,
            hooks: [],
            followed: [],
            tracing: false
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
            redirects: 0, elapsedMs: 0
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
            openedPaths: report.openedPaths.slice(0, 6)
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
        return report;
    }
};
