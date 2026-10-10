"use strict";

/*
 * Spike 1 agent — Stalker viability gate for the whatlicense -> Frida port.
 *
 * Answers the go/no-go questions the stage port depends on, on the real
 * target platform:
 *   S1  Stalker.follow(threadId) on another thread + transform + putCallout
 *   S2  instruction fields (address/size/mnemonic/opStr/next/operands)
 *   S3  effective-address computation from X86Operand + CpuContext
 *   S4  CpuContext register read
 *   S5  CpuContext register write (observable in the target's return value)
 *   S6  CpuContext flags availability (the PIN EFLAGS write primitive)
 *   S7  comparison neutralisation (fallback for the missing flags write)
 *   S8  pc write from a callout = the ExecuteAt primitive
 *   S9  raw instruction bytes (stage-2 modrm decode)
 *   S10 process memory write from a callout
 *   S11 unfollow + flush + garbageCollect, target keeps running
 *   S12 traced-instruction throughput
 *
 * TWO HARD-WON RULES, both verified on this spike:
 *   1. A Frida Instruction object is only valid inside the transform. Keep
 *      it in a closure and touch it later (in a callout) and every property
 *      access throws "Error: invalid operation" -- and a catch block that
 *      touches it again dies the same way, so the failure is silent.
 *      Everything a callout needs must be copied into a plain JS object
 *      during the transform (snapshot()).
 *   2. A CpuContext has NO flags field at all (neither eflags nor rflags;
 *      Object.keys() is empty). The PIN ExecuteAt(EFLAGS=0x200242)
 *      primitive therefore has no direct equivalent: a comparison has to be
 *      neutralised by rewriting the compared register or the memory it
 *      reads.
 *
 * The host drives it: setup() after the target printed its symbol addresses,
 * finish() after the target printed DONE.
 */

const MAGIC_EQ = 0xAABBCCDD;
const STORE_IMM = 0x55667788;
const PC_IMM = 0x11111111;
const REG_IMM = 0x12345678;

const IS_IA32 = Process.arch === "ia32";
const PC_REG = IS_IA32 ? "eip" : "rip";
const SP_REG = IS_IA32 ? "esp" : "rsp";

let plan = null;
let report = null;
let stats = null;
let followStart = 0;

function log(message) {
    console.log("spike1: " + message);
}

/* Console output from inside a Stalker callout is not reliably delivered;
 * send() is. Everything a handler learns is mirrored through emit(). */
function emit(payload) {
    try {
        send(payload);
    } catch (e) {
        /* nothing else we can do from a callout */
    }
}

function findImm(insns, imm) {
    const want = imm >>> 0;
    for (const insn of insns) {
        for (const operand of insn.operands) {
            if (operand.type === "imm" && (operand.value >>> 0) === want) {
                return insn;
            }
        }
    }
    return null;
}

function findMem(insns) {
    for (const insn of insns) {
        for (const operand of insn.operands) {
            if (operand.type === "mem") {
                return insn;
            }
        }
    }
    return null;
}

function scanFunction(start, limit) {
    const insns = [];
    let error = null;
    let addr = start;
    for (let i = 0; i < limit; i++) {
        let insn;
        try {
            insn = Instruction.parse(addr);
        } catch (e) {
            error = String(e);
            break;
        }
        insns.push(insn);
        if (insn.mnemonic === "ret" || insn.mnemonic === "retf") {
            break;
        }
        addr = insn.next;
    }
    return { insns: insns, error: error };
}

/* Copy everything a callout may need out of an Instruction. The Instruction
 * itself must not escape the transform (rule 1 above).
 *
 * NOTE: an instruction produced by the Stalker iterator reports a useless
 * `next` (it came back as the instruction's own size, not an address), so
 * the next address is computed from address + size. */
function snapshot(insn) {
    const nextAddress = insn.address.add(insn.size);
    const info = {
        address: insn.address.toString(),
        mnemonic: insn.mnemonic,
        opStr: insn.opStr,
        size: insn.size,
        next: nextAddress.toString(),
        operands: [],
        mem: null,
        regs: [],
        imms: [],
        bytes: []
    };
    for (const operand of insn.operands) {
        const entry = { type: operand.type, size: operand.size };
        if (operand.type === "mem") {
            const value = operand.value;
            entry.value = {
                base: value.base,
                index: value.index,
                scale: value.scale,
                disp: value.disp,
                segment: value.segment
            };
            info.mem = entry.value;
        } else if (operand.type === "reg") {
            entry.value = operand.value;
            info.regs.push(operand.value);
        } else if (operand.type === "imm") {
            entry.value = operand.value >>> 0;
            info.imms.push(entry.value);
        } else {
            entry.value = String(operand.value);
        }
        info.operands.push(entry);
    }
    const byteCount = Math.min(insn.size + 4, 16);
    for (let i = 0; i < byteCount; i++) {
        try {
            info.bytes.push(Memory.readU8(insn.address.add(i)));
        } catch (e) {
            break;
        }
    }
    return info;
}

/* Effective address of a memory operand, from the live CpuContext.
 * This is the primitive stages 1-4 need to turn "instruction + registers"
 * into "the address WinLicense is touching".
 *
 * RIP-relative operands are special: x86-64 computes the address from the
 * END of the instruction, and the callout's context.rip still points at the
 * instruction itself, so the base has to be supplied by the caller (it
 * measured a consistent 0xa / 0x6 byte error, exactly the instruction
 * length, when using context.rip). */
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

function describeMem(mem) {
    const parts = [];
    if (mem.segment !== undefined) { parts.push(mem.segment + ":"); }
    if (mem.base !== undefined) { parts.push(mem.base); }
    if (mem.index !== undefined) {
        parts.push("+" + mem.index + "*" + (mem.scale || 1));
    }
    if (mem.disp !== undefined) {
        parts.push((mem.disp >= 0 ? "+" : "") + mem.disp);
    }
    return parts.join("") || "<absolute 0>";
}

function describeDesc(mem) {
    return Object.keys(mem).map(function (key) {
        return key + ":" + String(mem[key]);
    }).join(",");
}

function ctxName(context, name) {
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

function note(test, ok, detail) {
    report.results.push({ test: test, ok: !!ok, detail: String(detail) });
}

function captureDiagnostics(role, info, context) {
    if (report.diag !== undefined) {
        return;
    }
    report.diag = {
        role: role,
        insn: info.address + " " + info.mnemonic + " " + info.opStr +
            " (size " + info.size + ", next " + info.next + ")",
        operands: info.operands.map(function (operand) {
            return operand.type + "/" + operand.size + "=" +
                (operand.type === "mem" ? describeDesc(operand.value)
                    : String(operand.value));
        }),
        contextKeys: Object.keys(context).join(","),
        pc: String(context[PC_REG]),
        sp: String(context[SP_REG]),
        eflags: String(context.eflags),
        rflags: String(context.rflags)
    };
    report.flagsField = {
        eflags: (context.eflags !== undefined),
        rflags: (context.rflags !== undefined),
        ownKeys: Object.keys(context).join(","),
        eax: String(context.eax),
        rax: String(context.rax)
    };
}

function handleCmp(info, context) {
    const seen = ++report.cmp.seen;
    const magic = Memory.readU32(plan.addrs.g_magic) >>> 0;
    const sample = {
        n: seen,
        pc: info.address,
        g_magic: "0x" + magic.toString(16),
        action: "none"
    };
    /* No flags write exists in Frida, so neutralise the comparison itself:
     * rewrite the compared register, or rewrite the memory it reads. */
    if (seen === 2) {
        if (info.regs.length > 0) {
            const target = ctxName(context, info.regs[0]);
            context[target] = MAGIC_EQ;
            sample.action = "reg " + target + " <- 0x" +
                MAGIC_EQ.toString(16) + " readback=" +
                context[target].toString();
        } else {
            sample.action = "no register operand: " + info.opStr;
        }
    }
    if (seen === 3) {
        Memory.writeU32(plan.addrs.g_magic, MAGIC_EQ);
        sample.action = "mem g_magic <- 0x" + MAGIC_EQ.toString(16) +
            " readback=0x" +
            (Memory.readU32(plan.addrs.g_magic) >>> 0).toString(16);
    }
    report.cmp.samples.push(sample);
    emit({ spike: "cmp", sample: sample });
}

function handleStore(info, context) {
    const out = { spike: "store", opStr: info.opStr };
    if (info.mem === null) {
        out.noMemOperand = true;
        emit(out);
        return;
    }
    const ea = computeEA(info.mem, context, info.next);
    out.ea = ea.toString();
    out.expect = plan.addrs.g_sink.toString();
    out.match = ea.equals(plan.addrs.g_sink);
    out.form = describeMem(info.mem);
    out.desc = describeDesc(info.mem);
    out.bytes = info.bytes.map(function (b) {
        return b.toString(16).padStart(2, "0");
    }).join(" ");
    const modrm = info.bytes[2];
    out.modrm = "0x" + modrm.toString(16);
    out.modrmFields = "mod=" + ((modrm >>> 6) & 3) + " reg=" +
        ((modrm >>> 3) & 7) + " rm=" + (modrm & 7);
    out.opcode = info.bytes[0].toString(16).padStart(2, "0") + " " +
        info.bytes[1].toString(16).padStart(2, "0");
    out.ripRelative = (info.mem.base === "rip" || info.mem.base === "eip");
    out.consistent = (((modrm >>> 6) & 3) === 0 && (modrm & 7) === 5)
        ? (out.ripRelative || info.mem.base === undefined) : true;
    report.store = out;
    emit(out);
}

function handlePcSkip(info, context) {
    const target = ptr(info.next);
    const name = ctxName(context, PC_REG);
    const out = {
        spike: "pcskip",
        name: name,
        from: info.address,
        to: info.next
    };
    try {
        context[name] = target;
        out.readback = context[name].toString();
        out.took = context[name].equals(target);
    } catch (e) {
        out.error = String(e);
    }
    report.pcskip = out;
    emit(out);
}

function handleReg(info, context) {
    const out = { spike: "reg", opStr: info.opStr };
    if (info.regs.length === 0) {
        out.noRegOperand = true;
        emit(out);
        return;
    }
    const name = ctxName(context, info.regs[0]);
    out.reg = info.regs[0];
    out.name = name;
    out.before = context[name].toString();
    context[name] = 0xDEADBEEF;
    out.after = context[name].toString();
    report.reg = out;
    emit(out);
}

/* Writing a register at an instruction that itself writes it is a no-op
 * (the instruction executes right after the callout and clobbers it), so the
 * observable register-write test rewrites eax/rax at the function's `ret`,
 * where the value is what the caller receives. */
function handleRegRet(info, context) {
    const out = { spike: "regret", opStr: info.opStr, next: info.next };
    const name = ctxName(context, IS_IA32 ? "eax" : "rax");
    out.name = name;
    out.before = context[name].toString();
    context[name] = 0xDEADBEEF;
    out.after = context[name].toString();
    report.regret = out;
    emit(out);
}

function handleLoad(info, context) {
    const out = { spike: "load", opStr: info.opStr };
    if (info.mem === null) {
        out.noMemOperand = true;
        emit(out);
        return;
    }
    const ea = computeEA(info.mem, context, info.next);
    out.ea = ea.toString();
    out.expect = plan.addrs.g_magic.toString();
    out.match = ea.equals(plan.addrs.g_magic);
    out.form = describeMem(info.mem);
    out.desc = describeDesc(info.mem);
    if (out.match) {
        out.value = "0x" + Memory.readU32(ea).toString(16);
    }
    report.load = out;
    emit(out);
}

function callout(role, info, context) {
    stats.callouts++;
    const roleKey = String(role);
    stats.roles[roleKey] = (stats.roles[roleKey] || 0) + 1;
    if (stats.callouts <= 10) {
        emit({
            spike: "callout",
            n: stats.callouts,
            role: roleKey,
            insn: info.address + " " + info.mnemonic + " " + info.opStr
        });
    }
    try {
        captureDiagnostics(role, info, context);
    } catch (e) {
        report.errors.push("diag: " + String(e));
    }
    try {
        if (role === "cmp") {
            handleCmp(info, context);
        } else if (role === "store") {
            handleStore(info, context);
        } else if (role === "pcskip") {
            handlePcSkip(info, context);
        } else if (role === "reg") {
            handleReg(info, context);
        } else if (role === "regret") {
            handleRegRet(info, context);
        } else if (role === "load") {
            handleLoad(info, context);
        } else {
            report.errors.push("unknown role " + roleKey + " at " +
                info.address);
        }
    } catch (e) {
        report.errors.push(role + "@" + info.address + ": " + String(e));
        emit({ spike: "handler-error", role: roleKey, error: String(e) });
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
        const role = plan.roles[address.toString()];
        if (role !== undefined) {
            stats.calloutsPlanned++;
            const info = snapshot(insn);
            iterator.putCallout(function (context) {
                callout(role, info, context);
            });
        }
        iterator.keep();
    }
}

/* Pick the thread to follow. The target blocks in a file-poll loop inside
 * the main module, so at setup time the main thread is usually executing
 * main-module code; if it happens to be inside a library call instead, fall
 * back to the lowest thread id (the main thread is created first). */
function pickThread() {
    const threads = Process.enumerateThreads();
    let inside = null;
    let lowest = null;
    for (const thread of threads) {
        if (thread.context.pc.compare(plan.moduleBase) >= 0 &&
            thread.context.pc.compare(plan.moduleEnd) < 0) {
            inside = thread.id;
        }
        if (lowest === null || thread.id < lowest) {
            lowest = thread.id;
        }
    }
    plan.threads = threads.map(function (thread) {
        const module = Process.findModuleByAddress(thread.context.pc);
        return thread.id + "@" + thread.context.pc +
            (module !== null ? "(" + module.name + ")" : "");
    });
    plan.threadChoice = inside !== null ? "pc-in-main-module" : "lowest-id";
    return inside !== null ? inside : lowest;
}

rpc.exports = {
    setup: function (options) {
        plan = {
            addrs: {
                g_magic: ptr(options.addrs.g_magic),
                g_flag: ptr(options.addrs.g_flag),
                g_sink: ptr(options.addrs.g_sink),
                g_sink2: ptr(options.addrs.g_sink2)
            },
            funcs: {
                branch: ptr(options.funcs.branch),
                store: ptr(options.funcs.store),
                pc: ptr(options.funcs.pc),
                pc2: ptr(options.funcs.pc2),
                reg: ptr(options.funcs.reg)
            },
            interceptor: null,
            roles: {},
            threads: [],
            threadChoice: "n/a",
            moduleBase: null,
            moduleEnd: null,
            threadId: null
        };
        report = {
            arch: Process.arch,
            pointerSize: Process.pointerSize,
            results: [],
            errors: [],
            scan: {},
            cmp: { seen: 0, samples: [] },
            store: {},
            load: {},
            reg: {},
            pcskip: {}
        };
        stats = {
            instructions: 0, inside: 0, outside: 0,
            calloutsPlanned: 0, callouts: 0, elapsedMs: 0, roles: {}
        };

        /* Resolve the main module range. */
        const modules = Process.enumerateModules();
        const main = modules[0];
        plan.moduleBase = main.base;
        plan.moduleEnd = main.base.add(main.size);
        report.scan.mainModule = main.name + " " + main.base + "+0x" +
            main.size.toString(16);

        /* Scan the four test functions and map the instructions we care
         * about. Everything is located by the immediate it embeds, so the
         * scan does not depend on compiler or optimization level. */
        const branch = scanFunction(plan.funcs.branch, 80);
        const store = scanFunction(plan.funcs.store, 80);
        const pc = scanFunction(plan.funcs.pc, 80);
        const pc2 = scanFunction(plan.funcs.pc2, 80);
        const reg = scanFunction(plan.funcs.reg, 80);
        report.scan.counts = {
            branch: branch.insns.length,
            store: store.insns.length,
            pc: pc.insns.length,
            pc2: pc2.insns.length,
            reg: reg.insns.length
        };
        report.scan.errors = [branch.error, store.error, pc.error,
            pc2.error, reg.error].filter(function (e) { return e !== null; });
        report.scan.mnemonics = branch.insns.map(function (i) {
            return i.mnemonic;
        }).join(",");

        const cmpInsn = findImm(branch.insns, MAGIC_EQ);
        const loadInsn = findMem(branch.insns);
        const storeInsn = findImm(store.insns, STORE_IMM);
        const pcInsn = findImm(pc.insns, PC_IMM);
        const regInsn = findImm(reg.insns, REG_IMM);

        report.scan.found = {
            cmp: cmpInsn ? cmpInsn.address + " " + cmpInsn.mnemonic + " " +
                cmpInsn.opStr : null,
            load: loadInsn ? loadInsn.address + " " + loadInsn.mnemonic +
                " " + loadInsn.opStr : null,
            store: storeInsn ? storeInsn.address + " " + storeInsn.mnemonic +
                " " + storeInsn.opStr : null,
            pc: pcInsn ? pcInsn.address + " " + pcInsn.mnemonic + " " +
                pcInsn.opStr : null,
            reg: regInsn ? regInsn.address + " " + regInsn.mnemonic + " " +
                regInsn.opStr : null
        };

        if (cmpInsn) { plan.roles[cmpInsn.address.toString()] = "cmp"; }
        if (loadInsn && loadInsn.address.toString() !==
            (cmpInsn ? cmpInsn.address.toString() : "")) {
            plan.roles[loadInsn.address.toString()] = "load";
        }
        if (storeInsn) { plan.roles[storeInsn.address.toString()] = "store"; }
        if (pcInsn) { plan.roles[pcInsn.address.toString()] = "pcskip"; }

        /* Instruction skipping cannot be done from a Stalker callout (the
         * pc write reads back but is not honoured), so the alternative is an
         * Interceptor hook that rewrites the pc before the instruction runs.
         * This is the second, Stalker-free half of the S8 question. */
        const pc2Insn = findImm(pc2.insns, 0x33333333);
        if (pc2Insn) {
            const skipTarget = pc2Insn.address.add(pc2Insn.size);
            plan.interceptor = {
                address: pc2Insn.address.toString(),
                target: skipTarget.toString()
            };
            const listener = Interceptor.attach(pc2Insn.address, {
                onEnter: function () {
                    this.context[PC_REG] = skipTarget;
                    emit({
                        spike: "pcskip2",
                        via: "Interceptor.attach",
                        name: PC_REG,
                        from: pc2Insn.address.toString(),
                        to: skipTarget.toString(),
                        readback: this.context[PC_REG].toString()
                    });
                }
            });
            report.scan.interceptor = plan.interceptor;
        }
        if (regInsn) { plan.roles[regInsn.address.toString()] = "reg"; }
        const retInsn = reg.insns.filter(function (i) {
            return i.mnemonic === "ret" || i.mnemonic === "retf";
        }).pop();
        if (retInsn) { plan.roles[retInsn.address.toString()] = "regret"; }

        /* Everything outside the main module runs natively. */
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
        report.scan.excludedModules = excluded;

        const threadId = pickThread();
        report.scan.threadId = threadId;
        report.scan.threads = plan.threads;
        report.scan.threadChoice = plan.threadChoice;
        if (threadId === null) {
            report.errors.push("no thread found to follow");
            return report;
        }
        plan.threadId = threadId;
        if (options.noStalker === true) {
            /* Control run: same target, same Interceptor, no Stalker. Tells
             * us whether the Interceptor redirection works at all, or
             * whether Stalker's JIT is what bypasses it. */
            report.scan.followed = false;
            report.scan.noStalker = true;
            report.scan.threadId = threadId;
            log("not following (noStalker control run)");
            return report;
        }
        followStart = Date.now();
        Stalker.follow(threadId, { transform: install });
        report.scan.followed = true;
        report.scan.roles = Object.keys(plan.roles).length;
        log("following thread " + threadId + ", roles=" +
            Object.keys(plan.roles).length);
        return report;
    },

    finish: function () {
        stats.elapsedMs = Date.now() - followStart;
        report.stats = stats;
        try {
            Stalker.unfollow(plan.threadId);
            Stalker.flush();
            Stalker.garbageCollect();
            report.scan.unfollowed = true;
        } catch (e) {
            report.errors.push("unfollow: " + String(e));
        }

        /* S1..S12 verdicts. The authoritative cross-check against the
         * target's own observations happens host-side (judge()); these are
         * the agent-side answers. */
        note("S1 stalker-callouts-fire", stats.callouts > 0,
            stats.callouts + " callouts, " + stats.instructions +
            " instructions traced (" + stats.inside + " in main module)" +
            " roles=" + JSON.stringify(stats.roles));
        note("S2 instruction-fields",
            report.scan.counts.branch > 1 && report.scan.errors.length === 0,
            "counts=" + JSON.stringify(report.scan.counts) +
            " mnemonics=" + report.scan.mnemonics);
        note("S3 ea-from-operands", report.store.match === true,
            "store ea=" + report.store.ea + " form=" + report.store.form +
            " desc=" + report.store.desc + " expect=" + report.store.expect +
            " loadMatch=" + report.load.match + " loadEa=" + report.load.ea);
        note("S4 register-read", typeof report.reg.before === "string",
            "reg=" + report.reg.reg + " (" + report.reg.name +
            ") before=" + report.reg.before);
        note("S5 register-write", report.reg.after === "0xdeadbeef",
            "wrote 0xdeadbeef, read back " + report.reg.after);
        note("S5b register-write-at-ret",
            report.regret !== undefined &&
            report.regret.after === "0xdeadbeef",
            JSON.stringify(report.regret));
        note("S6 flags-field-availability",
            report.flagsField !== undefined,
            "CpuContext flags field: " + JSON.stringify(report.flagsField) +
            " -> no EFLAGS write is possible, comparison-neutralisation is" +
            " the fallback");
        note("S7 cmp-neutralisation",
            report.cmp.samples.length >= 3,
            JSON.stringify(report.cmp.samples));
        note("S8 pc-write-callout", report.pcskip.took === true,
            JSON.stringify(report.pcskip));
        note("S8b pc-write-interceptor",
            report.scan.interceptor !== undefined,
            JSON.stringify(plan.interceptor) + " (Interceptor.attach instead " +
            "of a Stalker callout)");
        note("S9 raw-instruction-bytes",
            report.store.bytes !== undefined && report.store.consistent,
            "store bytes=" + report.store.bytes + " opcode=" +
            report.store.opcode + " modrm=" + report.store.modrm + " (" +
            report.store.modrmFields + ") ripRelative=" +
            report.store.ripRelative + " descriptorConsistent=" +
            report.store.consistent);
        note("S10 memory-write-callout",
            report.cmp.samples.length >= 3 &&
            report.cmp.samples[2].action.indexOf("readback=0xaabbccdd") >= 0,
            report.cmp.samples.length >= 3
                ? report.cmp.samples[2].action : "no sample #3");
        note("S11 unfollow", report.scan.unfollowed === true,
            "unfollow+flush+gc ok");
        note("S12 throughput", stats.elapsedMs > 0,
            Math.round(stats.instructions / (stats.elapsedMs / 1000)) +
            " instructions/s over " + stats.elapsedMs + " ms");
        report.diagnostics = report.diag;
        return report;
    }
};
