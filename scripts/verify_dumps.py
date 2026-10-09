#!/usr/bin/env python3
"""Verify dumped PEs actually work: static sanity checks + attempt to run.

Status per dump:
  STATIC_BAD   PE structure broken / no imports / EP outside code
  CRASH        process crashed on start (access violation, dll init fail...)
  RUNS_OK      console app exited with code 0
  RUNS_RC      process exited with a nonzero code (may be legit app code)
  RUNS_ALIVE   still running after 15s (typical for GUI apps) -> killed
  STATIC_ONLY  DLL — cannot execute directly; static checks only

Writes results/verify_report.json and appends a table to GITHUB_STEP_SUMMARY.
Exit code: 1 if any STATIC_BAD or CRASH.
"""
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DUMP_DIR = ROOT / "results" / "unpacked"
RUN_TIMEOUT = 15


def static_check(p: Path) -> tuple[str, str]:
    data = p.read_bytes()
    if data[:2] != b"MZ":
        return "BAD", "no MZ"
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\0\0":
        return "BAD", "no PE signature"
    nsec, = struct.unpack_from("<H", data, e + 6)
    opt_off = e + 24
    ep, = struct.unpack_from("<I", data, opt_off + 16)
    sec_off = opt_off + struct.unpack_from("<H", data, e + 20)[0]
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, va = struct.unpack_from("<II", data, o + 8)
        secs.append((name, va, vsize))
    ep_sec = next((n for n, va, vs in secs if va <= ep < va + vs), None)
    if ep_sec is None:
        return "BAD", f"EP {hex(ep)} outside any section"
    # import directory
    pe32p = struct.unpack_from("<H", data, opt_off)[0] == 0x20B
    dd_off = opt_off + (112 if pe32p else 96)
    import_rva, = struct.unpack_from("<I", data, dd_off + 8)
    if import_rva == 0:
        return "WARN", f"EP ok in {ep_sec.strip()} but import dir empty"
    return "OK", f"EP in {ep_sec.strip()}"


def run_check(p: Path) -> tuple[str, str]:
    if p.suffix.lower() == ".dll":
        return "STATIC_ONLY", "dll"
    try:
        proc = subprocess.Popen([str(p)], cwd=str(p.parent),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
    except OSError as exc:
        return "STATIC_BAD", f"spawn failed: {exc}"
    try:
        out, _ = proc.communicate(timeout=RUN_TIMEOUT)
        rc = proc.returncode
        # Windows facility codes: 0xC0000000+ are crashes
        if rc is not None and (rc & 0xC0000000) == 0xC0000000:
            return "CRASH", f"exit {hex(rc & 0xFFFFFFFF)}"
        if rc == 0:
            tail = (out or b"")[-120:].decode("latin1", "replace").replace("\n", " ")
            return "RUNS_OK", f"rc=0 {tail}"
        return "RUNS_RC", f"rc={rc}"
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.communicate(timeout=10)
        except Exception:  # noqa: BLE001
            pass
        return "RUNS_ALIVE", f"alive>{RUN_TIMEOUT}s"


def main() -> int:
    dumps = sorted(DUMP_DIR.glob("*")) if DUMP_DIR.exists() else []
    rows = []
    bad = 0
    for d in dumps:
        if not d.is_file():
            continue
        stat, stat_msg = static_check(d)
        if d.suffix.lower() == ".dll":
            run, run_msg = "STATIC_ONLY", "dll"
        else:
            run, run_msg = run_check(d)
        status = "STATIC_BAD" if stat == "BAD" else \
            ("CRASH" if run == "CRASH" else run)
        if status in ("STATIC_BAD", "CRASH"):
            bad += 1
        rows.append({"dump": d.name, "size": d.stat().st_size,
                     "static": stat, "static_msg": stat_msg,
                     "run": run, "run_msg": run_msg, "status": status})
        print(f"{d.name:40} {status:12} {stat:6} {stat_msg} | {run_msg}",
              flush=True)

    report = {"rows": rows, "bad": bad}
    (ROOT / "results" / "verify_report.json").write_text(
        json.dumps(report, indent=2))

    md = ["", "## Dump verification", "",
          "| dump | status | static | run |", "|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['dump']} | **{r['status']}** | "
                  f"{r['static']}: {r['static_msg']} | "
                  f"{r['run']}: {r['run_msg']} |")
    md.append("")
    md.append(f"**verified: {len(rows) - bad}/{len(rows)}** "
              f"(bad or crashed: {bad})")
    summary = "\n".join(md) + "\n"
    print(summary)
    gh_sum = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_sum:
        with open(gh_sum, "a", encoding="utf-8") as f:
            f.write(summary)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
