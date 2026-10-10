#!/usr/bin/env python3
"""Spike 1 host driver — Stalker viability gate (see spike1_agent.js).

Builds spikes/spike1_target.c for the current platform/bitness at one or
more optimization levels, spawns it under frida, installs the agent, and
merges the agent's report with the target's own DONE line into
results/spike1_<platform>_<arch>_O<opt>.json.

Everything here runs on the machine that will run the target: on this
project that is windows-latest (authoritative, ia32/x64) and, for fast
iteration, Linux x64 (API-shape only — Windows semantics still need CI).

Exit code is 0 when every spike question answered PASS, 1 otherwise.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPIKES = ROOT / "spikes"
RESULTS = ROOT / "results"
BUILD = RESULTS / "spike1_build"

IS_WINDOWS = sys.platform == "win32"
ARCH = "x64" if sys.maxsize > 2 ** 32 else "x86"

sys.path.insert(0, str(SPIKES))

import toolchain  # noqa: E402  (spikes/toolchain.py)


def build_target(opt: int) -> Path:
    BUILD.mkdir(parents=True, exist_ok=True)
    suffix = ".exe" if IS_WINDOWS else ""
    out = BUILD / f"spike1_target_{sys.platform}_{ARCH}_O{opt}{suffix}"
    result = toolchain.compile_c(SPIKES / "spike1_target.c", out, opt)
    if not result["ok"]:
        raise SystemExit(f"build failed: {result}")
    print(f"built {out} ({out.stat().st_size} bytes) with "
          f"{result['compiler']}", flush=True)
    return out


def normalize_addr(value: str) -> str:
    """`%p` prints without the 0x prefix on Windows (mingw and MSVC), and
    frida's ptr() then parses the hex digits as decimal and refuses."""
    text = str(value).strip()
    if not text.lower().startswith("0x"):
        text = "0x" + text
    return text


def parse_target_line(text: str, tag: str) -> dict:
    """Parse `ADDR a=%p b=%p` / `FUNC a=%p ...` / `DONE k=v ...` lines."""
    for line in text.splitlines():
        if not line.startswith(tag + " "):
            continue
        fields = {}
        for token in line[len(tag) + 1:].split():
            if "=" in token:
                key, value = token.split("=", 1)
                fields[key] = value
        return fields
    return {}


def run_one(binary: Path, opt: int, timeout: int,
            no_stalker: bool = False) -> dict:
    import frida

    workdir = BUILD / f"run_{sys.platform}_{ARCH}_O{opt}"
    workdir.mkdir(parents=True, exist_ok=True)
    go_file = workdir / "spike_go"
    exit_file = workdir / "spike_exit"
    for path in (go_file, exit_file):
        path.unlink(missing_ok=True)

    device = frida.get_local_device()
    output = {"text": ""}
    messages = []

    def on_output(pid, fd, data):
        output["text"] += data.decode("utf-8", "replace")

    def on_message(message, data):
        if message.get("type") == "send":
            messages.append(message["payload"])
        else:
            messages.append({"spike": "message", "raw": message})

    device.on("output", on_output)

    started = time.time()
    pid = device.spawn([str(binary)], cwd=str(workdir), stdio="pipe")
    session = device.attach(pid)
    agent_source = (SPIKES / "spike1_agent.js").read_text()
    script = session.create_script(agent_source)
    script.on("message", on_message)
    script.load()
    device.resume(pid)

    # Wait for the target to publish its symbol addresses, then instrument
    # it before any of the measured code runs (the target blocks on a file).
    deadline = time.time() + 30
    while time.time() < deadline:
        if "FUNC " in output["text"] and "ADDR " in output["text"]:
            break
        time.sleep(0.1)
    addrs = {k: normalize_addr(v)
             for k, v in parse_target_line(output["text"], "ADDR").items()}
    funcs = {k: normalize_addr(v)
             for k, v in parse_target_line(output["text"], "FUNC").items()}
    if not addrs or not funcs:
        return {"opt": opt, "error": "target never printed addresses",
                "target_stdout": output["text"]}

    setup = script.exports_sync.setup({"addrs": addrs, "funcs": funcs,
                                       "noStalker": no_stalker})
    go_file.write_text("go")

    deadline = time.time() + timeout
    while time.time() < deadline:
        if "DONE " in output["text"]:
            break
        time.sleep(0.2)
    done = parse_target_line(output["text"], "DONE")
    time.sleep(0.5)  # let the last callouts land before we ask for the report

    try:
        final = script.exports_sync.finish()
    except Exception as exc:  # noqa: BLE001
        final = {"error": f"finish rpc failed: {exc}"}

    exit_file.write_text("exit")
    try:
        device.kill(pid)
    except Exception:  # noqa: BLE001
        pass
    try:
        session.detach()
    except Exception:  # noqa: BLE001
        pass

    mode = "noStalker" if no_stalker else "stalker"
    verdict = judge(final, done, messages, mode)
    return {
        "opt": opt,
        "mode": mode,
        "binary": str(binary),
        "seconds": round(time.time() - started, 1),
        "target_stdout": output["text"],
        "done": done,
        "setup": setup,
        "messages": messages,
        "final": final,
        "verdict": verdict,
    }


def judge(final: dict, done: dict, messages: list,
          mode: str = "stalker") -> dict:
    """Cross-check the agent's own answers against the target's observations.

    The agent's self-report is not enough: register/pc/memory writes only
    count as working if the target's DONE line shows the effect. send()
    payloads are the callout-side ground truth (module-global mutations from
    a callout turned out to be unreliable to read back).
    """
    checks = {}
    for row in final.get("results", []):
        checks[row["test"]] = {"ok": row["ok"], "detail": row["detail"]}

    sends = [m for m in messages if isinstance(m, dict) and "spike" in m]
    by_kind = {}
    for message in sends:
        by_kind.setdefault(message["spike"], []).append(message)
    callouts = by_kind.get("callout", [])

    def num(name):
        value = done.get(name)
        if value is None:
            return None
        try:
            return int(value, 16) if len(value) > 4 else int(value)
        except ValueError:
            return None

    g_flag = num("g_flag")
    g_taken = num("g_taken")
    g_sink = num("g_sink")
    g_sink2 = num("g_sink2")
    reg = num("reg")
    g_hits = num("g_hits")
    g_sink3 = num("g_sink3")
    magic = num("magic")

    if mode == "noStalker":
        checks["T-pc-write-interceptor-skips-store"] = {
            "ok": g_sink3 == 0,
            "detail": f"g_sink3=0x{(g_sink3 or 0):08x} (want 0, i.e. "
                      f"skipped) -- Interceptor redirection WITHOUT Stalker",
        }
        checks["T-loop-completed"] = {
            "ok": g_hits == 8,
            "detail": f"g_hits={g_hits} (want 8)",
        }
        # In the control run only these two are meaningful; the Stalker-side
        # answers are reported as information, not as failures.
        required = ["T-pc-write-interceptor-skips-store", "T-loop-completed"]
        failed = [n for n in required if not checks.get(n, {}).get("ok")]
        return {"checks": checks, "failed": failed, "ok": not failed,
                "mode": mode, "required": required}

    checks["T-callouts-dispatched"] = {
        "ok": len(callouts) >= 5,
        "detail": "; ".join(f"#{c['n']} {c['role']} {c['insn']}"
                            for c in callouts),
    }
    # comparison neutralisation via the compared register (callout #2)
    checks["T-register-rewrite-steers-branch"] = {
        "ok": g_taken is not None and g_taken >= 1,
        "detail": f"g_taken={g_taken} (>=1 proves the rewritten register "
                  f"steered the cmp)",
    }
    # comparison neutralisation via the compared memory (callout #3)
    checks["T-memory-rewrite-steers-branch"] = {
        "ok": g_taken is not None and g_taken >= 2,
        "detail": f"g_taken={g_taken} (>=2 proves the memory rewrite steered "
                  f"the cmp)",
    }
    # register write observable in the target's return value
    checks["T-register-write-observable"] = {
        "ok": reg == 0xDEADBEEF,
        "detail": f"reg=0x{(reg or 0):08x} (want 0xdeadbeef)",
    }
    # pc write from a callout: readback works but the write is not honoured
    # (the store still happens) -> recorded, not required, as a limitation
    checks["T-pc-write-in-callout-honoured"] = {
        "ok": g_sink2 == 0,
        "detail": f"g_sink2=0x{(g_sink2 or 0):08x} (0 would mean the "
                  f"callout pc write was honoured)",
    }
    # Interceptor-based pc rewrite: the skipped store must not have happened
    checks["T-pc-write-interceptor-skips-store"] = {
        "ok": g_sink3 == 0,
        "detail": f"g_sink3=0x{(g_sink3 or 0):08x} (want 0, i.e. skipped)",
    }
    # EA computation: the store must have landed in g_sink
    checks["T-ea-store-target"] = {
        "ok": g_sink == 0x55667788,
        "detail": f"g_sink=0x{(g_sink or 0):08x} (want 0x55667788)",
    }
    # memory write from a callout: g_magic must end as MAGIC_EQ
    checks["T-memory-write-observable"] = {
        "ok": magic == 0xAABBCCDD,
        "detail": f"magic=0x{(magic or 0):08x} (want 0xaabbccdd)",
    }
    checks["T-loop-completed"] = {
        "ok": g_hits == 8,
        "detail": f"g_hits={g_hits} (want 8)",
    }
    checks["T-branch-taken"] = {
        "ok": g_flag == 1,
        "detail": f"g_flag={g_flag} (want 1)",
    }
    failed = [name for name, row in checks.items() if not row["ok"]]
    return {"checks": checks, "failed": failed, "ok": not failed}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opts", default="0,2",
                        help="comma separated optimization levels")
    parser.add_argument("--nostalker", action="store_true",
                        help="also run a control pass without Stalker")
    parser.add_argument("--timeout", type=int, default=90,
                        help="seconds to wait for the target's DONE line")
    args = parser.parse_args()

    RESULTS.mkdir(exist_ok=True)
    rows = []
    ok = True
    for opt in [int(o) for o in args.opts.split(",")]:
        try:
            binary = build_target(opt)
            row = run_one(binary, opt, args.timeout)
            rows.append(row)
            if args.nostalker:
                rows.append(run_one(binary, opt, args.timeout,
                                    no_stalker=True))
        except Exception as exc:  # noqa: BLE001
            # Keep the report shape even when a leg dies, so the artifact
            # still shows what happened instead of just missing.
            import traceback
            rows.append({"opt": opt, "error": f"{exc}",
                         "traceback": traceback.format_exc()})
            ok = False
        rows.append(row)
        verdict = row.get("verdict", {})
        failed = verdict.get("failed", ["<run error>"])
        if failed or row.get("error"):
            ok = False
        print(f"\n=== {sys.platform}/{ARCH} -O{opt} ===", flush=True)
        print(f"target: {row.get('target_stdout', row.get('error', ''))}",
              flush=True)
        for name, check in verdict.get("checks", {}).items():
            mark = "PASS" if check["ok"] else "FAIL"
            print(f"  [{mark}] {name}: {check['detail']}", flush=True)
        if row.get("error"):
            print(f"  [FAIL] run error: {row['error']}", flush=True)

    out = RESULTS / f"spike1_{sys.platform}_{ARCH}.json"
    out.write_text(json.dumps(rows, indent=2))
    print(f"\nwrote {out}", flush=True)

    summary = ["## Spike 1 — Stalker viability", ""]
    for row in rows:
        failed = row.get("verdict", {}).get("failed", [])
        summary.append(f"- `-O{row['opt']}`: "
                       f"{'PASS' if not failed else 'FAIL ' + ', '.join(failed)}")
    summary.append("")
    gh_sum = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_sum:
        with open(gh_sum, "a", encoding="utf-8") as handle:
            handle.write("\n".join(summary) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
