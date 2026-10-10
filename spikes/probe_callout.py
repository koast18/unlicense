#!/usr/bin/env python3
"""Minimal probe: what actually works inside a Stalker callout?

Answers, from inside a callout on the first traced instruction of a known
function, one question at a time via send():
  - is the CpuContext live / which fields exist (eflags vs rflags)
  - can we read process memory
  - can we read and WRITE a context register and the pc
  - can we mutate a JS module-global object (plain property, nested property,
    array push) and is that mutation visible to the RPC thread afterwards
  - does console.log work from a callout

Usage: probe_callout.py <path-to-spike1_target> [--func-addr 0x...]
"""
import json
import sys
import time
from pathlib import Path

import frida

AGENT = r"""
"use strict";

const seen = { count: 0, nested: { list: [] }, flags: null };
let plan = null;

function probe(role, insn, context) {
    seen.count++;
    const out = { callout: seen.count, role: role };
    function attempt(name, fn) {
        try {
            out[name] = String(fn());
        } catch (e) {
            out[name] = "ERR: " + String(e);
        }
    }
    attempt("pc", function () { return context.pc.toString(); });
    attempt("sp", function () { return context.sp.toString(); });
    attempt("pcField", function () { return String(context[Process.arch === "ia32" ? "eip" : "rip"]); });
    attempt("spField", function () { return String(context[Process.arch === "ia32" ? "esp" : "rsp"]); });
    attempt("eflags", function () { return String(context.eflags); });
    attempt("rflags", function () { return String(context.rflags); });
    attempt("contextKeys", function () { return Object.keys(context).join(","); });
    attempt("readU32", function () { return Memory.readU32(ptr(plan.addr)).toString(16); });
    attempt("writeU32", function () { Memory.writeU32(ptr(plan.addr), 0xCAFEBABE); return "ok"; });
    attempt("readBack", function () { return Memory.readU32(ptr(plan.addr)).toString(16); });
    attempt("regRead", function () { return context[plan.reg].toString(); });
    attempt("regWrite", function () { context[plan.reg] = 0x1234; return String(context[plan.reg]); });
    attempt("flagsWrite", function () {
        const name = (context.eflags !== undefined) ? "eflags" : "rflags";
        context[name] = 0x200242;
        return name + "=" + String(context[name]);
    });
    attempt("pcWrite", function () {
        context.pc = ptr(plan.addr);
        return String(context.pc);
    });
    attempt("globalPlain", function () { seen.plain = "set"; return String(seen.plain); });
    attempt("globalNested", function () { seen.nested.deep = "set"; return String(seen.nested.deep); });
    attempt("globalPush", function () { seen.nested.list.push("x"); return String(seen.nested.list.length); });
    attempt("json", function () { return JSON.stringify(seen.nested); });
    send({ probe: out });
    if (seen.count > 3) {
        Stalker.unfollow();
    }
}

rpc.exports = {
    setup: function (options) {
        plan = {
            addr: options.addr,
            reg: Process.arch === "ia32" ? "eax" : "rax"
        };
        const modules = Process.enumerateModules();
        for (const module of modules.slice(1)) {
            try { Stalker.exclude({ base: module.base, size: module.size }); } catch (e) { }
        }
        const threads = Process.enumerateThreads();
        const main = modules[0];
        let tid = null;
        for (const thread of threads) {
            if (thread.context.pc.compare(main.base) >= 0 &&
                thread.context.pc.compare(main.base.add(main.size)) < 0) {
                tid = thread.id;
                break;
            }
        }
        if (tid === null) { tid = threads[0].id; }
        Stalker.follow(tid, {
            transform: function (iterator) {
                let insn;
                while ((insn = iterator.next()) !== null) {
                    if (insn.address.toString() === plan.addr) {
                        const current = insn;
                        iterator.putCallout(function (context) {
                            probe("target", current, context);
                        });
                    }
                    iterator.keep();
                }
            }
        });
        return { followed: tid, addr: plan.addr };
    },
    dump: function () { return seen; }
};
"""


def main() -> int:
    target = Path(sys.argv[1]).resolve()
    addr = sys.argv[sys.argv.index("--func-addr") + 1] if "--func-addr" in sys.argv else None
    workdir = target.parent / "probe_run"
    workdir.mkdir(exist_ok=True)
    go = workdir / "spike_go"
    exit_file = workdir / "spike_exit"
    go.unlink(missing_ok=True)
    exit_file.unlink(missing_ok=True)

    device = frida.get_local_device()
    out = {"text": ""}
    device.on("output", lambda pid, fd, data: out.__setitem__(
        "text", out["text"] + data.decode("utf-8", "replace")))
    pid = device.spawn([str(target)], cwd=str(workdir), stdio="pipe")
    session = device.attach(pid)
    script = session.create_script(AGENT)
    probes = []
    script.on("message", lambda message, data: probes.append(message))
    script.load()
    device.resume(pid)

    deadline = time.time() + 20
    while time.time() < deadline and "FUNC " not in out["text"]:
        time.sleep(0.1)
    if addr is None:
        line = [l for l in out["text"].splitlines() if l.startswith("FUNC ")]
        addr = line[0].split("branch=")[1].split()[0] if line else None
    print("target addr:", addr, flush=True)
    setup = script.exports_sync.setup({"addr": addr})
    print("setup:", setup, flush=True)
    go.write_text("go")
    time.sleep(3)
    print("seen from RPC thread:", json.dumps(script.exports_sync.dump()),
          flush=True)
    for message in probes:
        if message.get("type") == "send":
            print("PROBE:", json.dumps(message["payload"], indent=1),
                  flush=True)
        else:
            print("MSG:", json.dumps(message)[:400], flush=True)
    exit_file.write_text("exit")
    try:
        device.kill(pid)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
