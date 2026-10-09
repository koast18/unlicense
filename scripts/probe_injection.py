#!/usr/bin/env python3
"""Probe why frida injection fails on some samples: run each target naked
(no frida) and then via frida spawn+attach, and report which side dies.

For every sample matching this interpreter's bitness:
  A) naked run for 6s -> alive / exited(rc)
  B) frida spawn + attach + resume -> attach OK / ProcessNotResponding
Then compare: if naked run dies immediately too -> the process itself fails
to start (missing runtime / crash on init), otherwise -> anti-frida behavior.

Writes results/probe_report.json + markdown to GITHUB_STEP_SUMMARY.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
NAKED_SECS = 6

# targets to probe (label -> nothing; all manifest entries with arch match)
# a handful of known-bad + one known-good control per arch
CONTROL = {"x64": "drchost", "x86": "vc_example"}


def interpreter_bitness() -> str:
    return "x64" if sys.maxsize > 2**32 else "x86"


def naked_run(exe: Path) -> str:
    try:
        proc = subprocess.Popen([str(exe)], cwd=str(exe.parent),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
    except OSError as exc:
        return f"SPAWN_FAIL {exc}"
    t0 = time.time()
    while time.time() - t0 < NAKED_SECS:
        if proc.poll() is not None:
            rc = proc.returncode
            tag = f"EXIT rc={rc}" + (f" (crash {hex(rc & 0xFFFFFFFF)})"
                                     if rc is not None
                                     and (rc & 0xC0000000) == 0xC0000000
                                     else "")
            return tag
        time.sleep(0.3)
    proc.kill()
    try:
        proc.communicate(timeout=5)
    except Exception:  # noqa: BLE001
        pass
    return f"ALIVE>{NAKED_SECS}s"


def frida_probe(exe: Path) -> str:
    import frida
    dev = frida.get_local_device()
    pid = None
    try:
        pid = dev.spawn([str(exe)])
    except Exception as exc:  # noqa: BLE001
        return f"SPAWN_ERR {type(exc).__name__}: {exc}"
    try:
        session = dev.attach(pid)
        dev.resume(pid)
        time.sleep(1.5)
        try:
            session.detach()
        except Exception:  # noqa: BLE001
            pass
        return f"ATTACH_OK pid={pid}"
    except Exception as exc:  # noqa: BLE001
        msg = f"{type(exc).__name__}: {str(exc)[:110]}"
        try:
            dev.kill(pid)
        except Exception:  # noqa: BLE001
            pass
        return f"ATTACH_FAIL {msg}"


def main() -> int:
    import frida  # noqa: F401 - fail early if missing
    print(f"frida {frida.__version__}, bitness {interpreter_bitness()}")
    manifest = json.loads((RESULTS / "manifest.json").read_text())
    bitness = interpreter_bitness()
    rows = []
    for entry in manifest:
        label = entry["label"]
        if not entry["downloaded"] or not entry["pes"]:
            continue
        exes = [p for p in entry["pes"]
                if p["path"].lower().endswith(".exe")
                and p["arch"] == bitness
                and p.get("version") is not None]
        if not exes:
            continue
        exe = ROOT / exes[0]["path"]
        print(f"[{label}] naked ...", flush=True)
        n = naked_run(exe)
        print(f"[{label}] naked -> {n}", flush=True)
        print(f"[{label}] frida ...", flush=True)
        f = frida_probe(exe)
        print(f"[{label}] frida -> {f}", flush=True)
        rows.append({"label": label, "arch": exes[0]["arch"],
                     "naked": n, "frida": f,
                     "control": label == CONTROL.get(bitness)})

    (RESULTS / f"probe_{bitness}.json").write_text(
        json.dumps({"bitness": bitness, "rows": rows}, indent=2))

    md = [f"## Probe report (python {bitness})", "",
          "| sample | naked run | frida spawn+attach | verdict |",
          "|---|---|---|---|"]
    for r in rows:
        if r["naked"].startswith("EXIT") or r["naked"].startswith("SPAWN"):
            verdict = "process dies on its own (runtime/anticrash)"
        elif r["frida"].startswith("ATTACH_FAIL"):
            verdict = "anti-frida / injection blocked"
        else:
            verdict = "baseline ok"
        md.append(f"| {r['label']}{' (ctrl)' if r['control'] else ''} | "
                  f"{r['naked']} | {r['frida']} | {verdict} |")
    summary = "\n".join(md) + "\n"
    print(summary, flush=True)
    gh_sum = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_sum:
        with open(gh_sum, "a", encoding="utf-8") as f:
            f.write(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
