'use strict';

/*
 * whatlicense Stage 2 -- find and bypass the hash_3 comparison.
 *
 * Port of wl-extract/staging/stage2.cpp to the Frida stack. This module is
 * written to be merged into spikes/spike2_agent.js once Stage 1 is green; it
 * is kept separate so it cannot break the Stage 0/1 agent that is currently
 * being validated on real samples.
 *
 * ---------------------------------------------------------------------------
 * What the PIN original does (stage2.cpp, 141 lines)
 *
 *   init(dec_lic):  hash3 = rword(dec_lic + 0x33)   -- the 2-byte value we
 *                   wrote into our own license, at offset 0x33.
 *
 *   sub-stage 1:    watch reads. When a read of (dec_lic + 0x33) with size 2
 *                   is seen, the program has picked up our hash_3. WL reads
 *                   the value and then shuffles it through push/pop several
 *                   times before using it, so this read only narrows the
 *                   search -- it is not yet the comparison.
 *                   -> sub-stage 2
 *
 *   sub-stage 2:    look for 'cmp word ptr [reg1], reg2' (isWordPtrRegCmp).
 *                   Read both operands. Exactly one of them is the hash_3 we
 *                   generated; the other one is the value the program
 *                   actually expects, i.e. the answer. Save it as hash.hash_3.
 *                   Then make the comparison pass:
 *                       PIN_SetContextReg(ctxt, REG_EFLAGS, 0x200242);
 *                       PIN_SetContextReg(ctxt, REG_INST_PTR, addr + 3);
 *                       PIN_ExecuteAt(ctxt);
 *                   -> sub-stage 3
 *
 *   sub-stage 3:    stage inactive, mgr.advance(dec_lic) -- Stage 3 needs the
 *                   decrypted license buffer.
 *
 * ---------------------------------------------------------------------------
 * Why the PIN bypass cannot be ported literally
 *
 * Spike 1 established, on both Windows x86 and x64 (run 38018902214):
 *   - Frida's CpuContext has NO flags field at all -- eflags/rflags are
 *     undefined and Object.keys() is empty. REG_EFLAGS has no equivalent.
 *   - Writing the pc does not take effect: in a Stalker callout
 *     context.rip reads back correctly but the instruction still executes;
 *     writing this.context.rip in an Interceptor onEnter is equally inert.
 *
 * So neither half of the PIN bypass works. Spike 1 also verified the
 * replacement: rewriting the compared register (or the memory it reads)
 * genuinely reverses the branch (probe target reported g_taken=6, g_flag=1).
 *
 * The port therefore neutralises the comparison instead of forcing the
 * flags: whichever operand equals our hash_3 is overwritten with the value
 * it is compared against, so the cmp produces equality on its own and the
 * program's own branch does the right thing. The expected value is still
 * logged, which is the actual product of this stage.
 *
 * ---------------------------------------------------------------------------
 * Integration contract (what spike2_agent.js must provide)
 *
 *   plan            -- the shared plan object (we add plan.stage2)
 *   plan.stage1.decLic   -- the RSA-decrypted license buffer from Stage 1
 *   IS_IA32, PC_REG, SP_REG
 *   emit(obj)       -- the agent's send() wrapper
 *   armGuardFor(pageAddr, len, onHit)  -- or the guard helpers this file
 *                      expects to be injected; see wireStage2() below
 *   registerInsnHook(fn)  -- called from the Stalker transform for every
 *                      instruction; fn(insn, iterator) returns true if it
 *                      handled the instruction
 *
 * Call startStage2(decLic) from the point where Stage 1 sets
 * report.stage1Complete = true.
 */

/* ------------------------------------------------------------ constants --- */

/* Offset of hash_3 inside the decrypted license buffer (stage2.cpp init). */
const HASH3_OFFSET = 0x33;

/* Size of the compared values: 'cmp word ptr [...]' is 16-bit. */
const HASH3_SIZE = 2;

/* Instruction encodings isWordPtrRegCmp accepts:
 *   66 39 /r   CMP r/m16, r16
 *   66 3B /r   CMP r16,  r/m16
 * Both are 3 bytes when the memory operand uses no SIB/displacement, which
 * is the case the PIN original relies on ("esp or ebp are involved ... which
 * they never should be"). We do not hardcode +3 -- see stage2InsnLength. */
const CMP_RM16_R16 = 0x39;
const CMP_R16_RM16 = 0x3B;

/* ---------------------------------------------------------------- state --- */

function stage2State(plan) {
    if (plan.stage2 === undefined) {
        plan.stage2 = {
            active: false,
            sub: 0,
            decLic: null,
            hash3: 0,
            realHash3: null,
            /* guard page around dec_lic + 0x33, same mechanism as Stage 1 */
            guardStart: null,
            guardLength: 0,
            guardArmed: false,
            guardHits: 0,
            /* sub-stage 2 bookkeeping */
            cmpSeen: 0,
            cmpHitLogged: false,
            bypasses: 0,
            lastCmp: null
        };
    }
    return plan.stage2;
}

function stage2Log(plan, event, detail) {
    plan.emit({ spike: "stage2", event: event, detail: detail });
}

/* --------------------------------------------------------- sub-stage 1 --- */

/* Stage 2 starts here. `decLic` is the buffer Stage 1 produced. */
function startStage2(plan, decLic) {
    const s2 = stage2State(plan);
    s2.active = true;
    s2.sub = 1;
    s2.decLic = ptr(decLic);

    /* The hash_3 we wrote into our own license. It is read back by the
     * program, so it is the marker that identifies the comparison. */
    s2.hash3 = s2.decLic.add(HASH3_OFFSET).readU16();
    stage2Log(plan, "start", "dec_lic=" + s2.decLic +
        " hash3=0x" + s2.hash3.toString(16));

    /* Landmark for sub-stage 1: the first read of dec_lic + 0x33. Same
     * guard-page trick as Stage 1 sub-stage 1 -- per-read callouts are far
     * too slow (that is exactly why Stage 1 moved off them), and a guard
     * page costs nothing until it is touched. */
    const target = s2.decLic.add(HASH3_OFFSET);
    const pageSize = Process.pageSize;
    const start = target.and(ptr(pageSize - 1).not());
    const length = pageSize;
    s2.guardStart = start;
    s2.guardLength = length;
    plan.armGuardFor(start, length, stage2OnHash3PageAccess);
    stage2Log(plan, "guard", "page=" + start + "+0x" +
        length.toString(16) + " armed=" + plan.guardArmedFor(start));
}

/* Guard-page handler for sub-stage 1. Returns true when the access was ours
 * (and therefore consumed), false to let the exception reach the target. */
function stage2OnHash3PageAccess(plan, details) {
    const s2 = stage2State(plan);
    if (!s2.active || s2.sub !== 1) {
        return false;
    }
    const address = stage2AccessAddress(details);
    if (address === null) {
        return false;
    }
    if (address.compare(s2.guardStart) < 0 ||
        address.compare(s2.guardStart.add(s2.guardLength)) >= 0) {
        return false;
    }
    s2.guardHits++;
    const operation = stage2AccessOperation(details);
    const isHash3Read = operation === "read" &&
        address.compare(s2.decLic.add(HASH3_OFFSET)) === 0;
    if (!isHash3Read) {
        /* Something else in the page was touched: re-arm and carry on. */
        plan.rearmGuardFor(s2.guardStart, s2.guardLength);
        return true;
    }
    stage2Log(plan, "hash3-read", "pc=" +
        (details.context ? details.context[plan.PC_REG] : "?") +
        " hits=" + s2.guardHits);
    /* The guard bit is already cleared by the OS; the instruction retries
     * and succeeds. Move to the comparison search. */
    s2.sub = 2;
    plan.stage2ScanCmp = true;
    return true;
}

/* --------------------------------------------------------- sub-stage 2 --- */

/* Called from the Stalker transform for every instruction while
 * plan.stage2ScanCmp is set. Returns true when the instruction was ours.
 *
 * We cannot read register/memory values here (the Instruction object is only
 * valid inside the transform, and touching it from a callout throws --
 * verified in Spike 1). So the transform only *recognises* the candidate and
 * schedules a callout via putCallout; the callout does the value work with a
 * real CpuContext. */
function stage2RecogniseCmp(plan, insn) {
    if (!plan.stage2ScanCmp) {
        return false;
    }
    if (insn.mnemonic !== "cmp" || insn.operands.length !== 2) {
        return false;
    }
    /* isWordPtrRegCmp: one memory operand and one general register, both
     * 16-bit. The operand descriptor gives us the size. */
    let mem = null;
    let reg = null;
    for (const operand of insn.operands) {
        if (operand.type === "mem") {
            mem = operand;
        } else if (operand.type === "reg") {
            reg = operand;
        }
    }
    if (mem === null || reg === null) {
        return false;
    }
    const memSize = stage2OperandSizeBits(mem);
    if (memSize !== 16) {
        return false;
    }
    plan.stage2CmpSite = {
        address: insn.address,
        size: insn.size,
        memBase: mem.value,
        regName: reg.value
    };
    return true;
}

/* The callout for a recognised comparison. `context` is a real CpuContext,
 * so this is where the values are read and the bypass is applied. */
function stage2ApplyCmp(plan, context) {
    const s2 = stage2State(plan);
    const site = plan.stage2CmpSite;
    if (!s2.active || s2.sub !== 2 || site === undefined) {
        return;
    }
    s2.cmpSeen++;

    /* Resolve the memory operand's effective address from the live context
     * and read both compared values. */
    const ea = stage2EffectiveAddress(context, site.memBase);
    if (ea === null) {
        return;
    }
    let memVal;
    try {
        memVal = ea.readU16();
    } catch (e) {
        return;
    }
    const regVal = context[site.regName].and(0xffff).toUInt32();

    if (!s2.cmpHitLogged) {
        s2.cmpHitLogged = true;
        stage2Log(plan, "cmp-candidate", "pc=" + site.address +
            " mem@ " + ea + "=0x" + memVal.toString(16) +
            " reg " + site.regName + "=0x" + regVal.toString(16) +
            " ours=0x" + s2.hash3.toString(16));
    }

    /* Exactly one operand is the hash_3 we generated; the other is the value
     * the program expects. That other one is the answer. */
    let expected = null;
    let oursIsMem = false;
    if (memVal !== s2.hash3) {
        if (regVal !== s2.hash3) {
            /* Neither operand is ours -- keep looking (stage2.cpp does the
             * same). This happens for every other word comparison WL makes. */
            return;
        }
        expected = memVal;
        oursIsMem = false;   /* the register holds our value */
    } else {
        expected = regVal;
        oursIsMem = true;    /* the memory operand holds our value */
    }

    s2.realHash3 = expected;
    s2.sub = 3;
    plan.stage2ScanCmp = false;

    stage2Log(plan, "hash3-found", "hash_3=" + expected +
        " (0x" + expected.toString(16) + ") ours=" + s2.hash3 +
        " oursIsMem=" + oursIsMem);

    /* Neutralise the comparison: overwrite whichever operand holds our
     * hash_3 with the expected value, so the cmp sets the flags on its own
     * and the program's own branch is taken. (EFLAGS is not writable and the
     * pc cannot be advanced -- both verified in Spike 1.) */
    if (oursIsMem) {
        ea.writeU16(expected);
        stage2Log(plan, "bypass", "mem@ " + ea + " <- 0x" +
            expected.toString(16));
    } else {
        context[site.regName] = stage2SetLow16(context[site.regName],
            expected);
        stage2Log(plan, "bypass", site.regName + " <- 0x" +
            expected.toString(16));
    }
    s2.bypasses++;
    s2.lastCmp = site.address.toString();

    /* Sub-stage 3: hand the decrypted buffer to Stage 3. */
    stage2Log(plan, "complete", "advance(dec_lic=" + s2.decLic + ")");
    plan.emit({ spike: "stage2_complete",
                hash3: expected,
                decLic: s2.decLic.toString(),
                cmpSite: site.address.toString() });
}

/* --------------------------------------------------------------- helpers -- */

function stage2AccessAddress(details) {
    const memory = details.memory || null;
    if (memory !== null && memory.address !== undefined &&
        memory.address !== null) {
        return memory.address;
    }
    if (details.address !== undefined && details.address !== null) {
        return details.address;
    }
    return null;
}

function stage2AccessOperation(details) {
    const memory = details.memory || null;
    if (memory !== null && memory.operation) {
        return memory.operation;
    }
    /* A guard-page violation does not always carry the memory descriptor;
     * assume a read, which is the case we are hunting for. The value checks
     * in stage2ApplyCmp still reject anything that is not ours. */
    return "read";
}

/* Effective address of a memory operand from a live CpuContext. Only the
 * forms the PIN original accepts are handled: [reg] with no SIB and no
 * displacement. Anything else returns null and the candidate is skipped. */
function stage2EffectiveAddress(context, base) {
    if (base === undefined || base === null) {
        return null;
    }
    const name = String(base).trim();
    if (!Object.prototype.hasOwnProperty.call(context, name)) {
        return null;
    }
    return context[name];
}

function stage2OperandSizeBits(operand) {
    /* Frida reports the operand size in bits on the descriptor; fall back to
     * the register width when it is absent. */
    if (operand.size !== undefined && operand.size !== null) {
        return operand.size;
    }
    return null;
}

/* Write a 16-bit value into the low half of a 32/64-bit register value
 * without disturbing the upper bits. */
function stage2SetLow16(current, value) {
    const upper = current.and(ptr(0xffff).not());
    return upper.or(ptr(value & 0xffff));
}

/* ---------------------------------------------------------------- export -- */

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        HASH3_OFFSET,
        startStage2,
        stage2OnHash3PageAccess,
        stage2RecogniseCmp,
        stage2ApplyCmp,
        stage2State
    };
}