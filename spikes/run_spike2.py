#!/usr/bin/env python3
"""Spike 2 host driver — Stage 0 (license copy location) of the whatlicense
pipeline, ported to Frida.

Two modes:

  --local   build spikes/spike2_target.c, write a dummy license, run the
            target with the agent attached (mmap/munmap hooks on Linux) and
            require the full Stage 0 result: the license is recognised when
            mapped, byte-store candidates are recorded, and after the unmap
            one candidate holds the license head -> lic_copy. Seconds, no CI.

  --ci      run a real WinLicense sample (from results/manifest.json, built by
            scripts/prepare_samples.py) with the NtCreateFile redirect,
            MapViewOfFile / UnmapViewOfFile hooks and the dummy license
            produced by wl-lic. A sample that never opens regkey.dat is
            reported as inconclusive, not as a harness failure.

The acceptance criterion for both is Stage 0's own: find `lic_copy`.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPIKES = ROOT / "spikes"
RESULTS = ROOT / "results"
BUILD = RESULTS / "spike2_build"

IS_WINDOWS = sys.platform == "win32"
ARCH = "x64" if sys.maxsize > 2 ** 32 else "x86"

sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(SPIKES))

import toolchain  # noqa: E402

HEAD_LEN = 8


def build_target(opt: int) -> Path:
    BUILD.mkdir(parents=True, exist_ok=True)
    suffix = ".exe" if IS_WINDOWS else ""
    out = BUILD / f"spike2_target_{sys.platform}_{ARCH}_O{opt}{suffix}"
    result = toolchain.compile_c(SPIKES / "spike2_target.c", out, opt)
    if not result["ok"]:
        raise SystemExit(f"build failed: {result}")
    print(f"built {out} ({out.stat().st_size} bytes) with "
          f"{result['compiler']}", flush=True)
    return out


def make_dummy_license(path: Path, size: int = 4096) -> str:
    """A stand-in for wl-lic's dummy license: the only thing Stage 0 needs is
    the first 8 bytes (it compares the head of the mapping)."""
    head = bytes([0x57, 0x4C, 0x44, 0x55, 0x4D, 0x59, 0x30, 0x31])  # WLDUMY01
    body = bytes((i * 7 + 3) & 0xFF for i in range(size - HEAD_LEN))
    path.write_bytes(head + body)
    return head.hex()


def windows_nt_path(path: Path) -> str:
    absolute = str(path.resolve())
    if not absolute.startswith("\\\\"):
        return "\\??\\" + absolute
    return absolute


def run_agent(exe: Path, workdir: Path, head_hex: str, nt_path: str,
              duration: int, license_file: str) -> dict:
    import frida

    workdir.mkdir(parents=True, exist_ok=True)
    go_file = workdir / "spike_go"
    exit_file = workdir / "spike_exit"
    for path in (go_file, exit_file):
        path.unlink(missing_ok=True)

    device = frida.get_local_device()
    output = {"text": ""}
    messages = []

    device.on("output", lambda pid, fd, data: output.__setitem__(
        "text", output["text"] + data.decode("utf-8", "replace")))

    def on_message(message, data):
        if message.get("type") == "send":
            messages.append(message["payload"])
        else:
            messages.append({"spike": "message", "raw": message})

    started = time.time()
    pid = device.spawn([str(exe)], cwd=str(workdir), stdio="pipe")
    session = device.attach(pid)
    script = session.create_script((SPIKES / "spike2_agent.js").read_text())
    script.on("message", on_message)
    script.load()
    device.resume(pid)

    # The agent arms its hooks from setup(); the target waits on the go-file.
    time.sleep(1.5)
    setup = script.exports_sync.setup({
        "headHex": head_hex,
        "ntPath": nt_path,
        "licenseFile": license_file
    })
    go_file.write_text("go")

    status = None
    deadline = time.time() + duration
    last_report = 0.0
    while time.time() < deadline:
        time.sleep(2)
        try:
            status = script.exports_sync.status()
        except Exception as exc:  # noqa: BLE001
            status = {"error": str(exc)}
            break
        if status.get("licCopy"):
            print(f"  stage0 complete: lic_copy={status['licCopy']}",
                  flush=True)
            break
        if time.time() - last_report >= 15:
            last_report = time.time()
            print(f"  ... {status}", flush=True)
    print(f"  status: {json.dumps(status)}", flush=True)

    try:
        final = script.exports_sync.finish()
    except Exception as exc:  # noqa: BLE001
        final = {"error": f"finish rpc failed: {exc}"}

    exit_file.write_text("exit")
    time.sleep(0.3)
    try:
        device.kill(pid)
    except Exception:  # noqa: BLE001
        pass
    try:
        session.detach()
    except Exception:  # noqa: BLE001
        pass

    return {
        "exe": str(exe),
        "seconds": round(time.time() - started, 1),
        "target_stdout": output["text"],
        "setup": setup,
        "status": status,
        "messages": messages,
        "final": final,
    }


def judge_local(run: dict, head_hex: str) -> dict:
    final = run.get("final", {})
    mapped = bool(final.get("licenseMappedTo"))
    candidates = final.get("candidates") or []
    lic_copy = final.get("licCopy")
    checks = {
        "license-mapped": {
            "ok": mapped,
            "detail": f"mapping at {final.get('licenseMappedTo')} had head "
                      f"{head_hex}",
        },
        "candidates-recorded": {
            "ok": len(candidates) >= 1,
            "detail": f"{len(candidates)} candidate addresses from byte "
                      f"stores (planned callouts: "
                      f"{final.get('stats', {}).get('byteStoresPlanned')}, "
                      f"byte stores seen: "
                      f"{final.get('stats', {}).get('byteWrites')})",
        },
        "lic-copy-found": {
            "ok": lic_copy is not None,
            "detail": f"lic_copy={lic_copy} first bytes="
                      f"{final.get('licCopyFirstBytes')} (want {head_hex})",
        },
    }
    failed = [name for name, row in checks.items() if not row["ok"]]
    return {"checks": checks, "failed": failed, "ok": not failed,
            "status": "stage0-complete" if not failed else "failed"}


def judge_ci(run: dict, head_hex: str) -> dict:
    final = run.get("final", {})
    stats = final.get("stats", {})
    redirects = stats.get("redirects", 0)
    opens = stats.get("fileOpens", 0)
    mapped = bool(final.get("licenseMappedTo"))
    candidates = final.get("candidates") or []
    lic_copy = final.get("licCopy")
    checks = {
        "license-open-redirected": {
            "ok": redirects >= 1,
            "detail": f"{redirects} regkey.dat open(s) redirected of "
                      f"{opens} file opens seen; original path "
                      f"{final.get('originalLicensePath')}",
        },
        "license-mapped": {
            "ok": mapped,
            "detail": f"mapping at {final.get('licenseMappedTo')}",
        },
        "candidates-recorded": {
            "ok": len(candidates) >= 1,
            "detail": f"{len(candidates)} candidates from byte stores "
                      f"(byte stores seen: {stats.get('byteWrites')})",
        },
        "lic-copy-found": {
            "ok": lic_copy is not None,
            "detail": f"lic_copy={lic_copy}",
        },
    }
    failed = [name for name, row in checks.items() if not row["ok"]]
    if lic_copy is not None:
        status = "stage0-complete"
    elif opens == 0:
        status = "inconclusive"
    else:
        status = "failed"
    return {"checks": checks, "failed": failed, "ok": not failed,
            "status": status}


def local_pass(opts, args) -> int:
    rows = []
    ok = True
    for opt in opts:
        binary = build_target(opt)
        workdir = BUILD / f"local_O{opt}"
        shutil.rmtree(workdir, ignore_errors=True)
        workdir.mkdir(parents=True, exist_ok=True)
        dummy = workdir / "regkey.dat"
        head_hex = make_dummy_license(dummy)
        print(f"\n=== local {sys.platform}/{ARCH} -O{opt} (head {head_hex}) ===",
              flush=True)
        run = run_agent(binary, workdir, head_hex, windows_nt_path(dummy),
                        args.duration, str(dummy))
        verdict = judge_local(run, head_hex)
        run["verdict"] = verdict
        rows.append(run)
        print(f"  target: {run['target_stdout'].strip()}", flush=True)
        for name, check in verdict["checks"].items():
            mark = "PASS" if check["ok"] else "FAIL"
            print(f"  [{mark}] {name}: {check['detail']}", flush=True)
        if not verdict["ok"]:
            ok = False
    out = RESULTS / f"spike2_local_{sys.platform}_{ARCH}.json"
    RESULTS.mkdir(exist_ok=True)
    out.write_text(json.dumps(rows, indent=2))
    print(f"\nwrote {out}", flush=True)
    return 0 if ok else 1


def ci_pass(args) -> int:
    manifest_path = RESULTS / "manifest.json"
    if not manifest_path.exists():
        raise SystemExit("results/manifest.json missing (run "
                         "scripts/prepare_samples.py first)")
    manifest = json.loads(manifest_path.read_text())
    by_label = {entry["label"]: entry for entry in manifest}
    dummy = Path(args.dummy)
    if not dummy.exists():
        # Stage 0 only cares about the license head, so a synthetic dummy
        # still exercises the whole redirect/map/copy/unmap path. Reported
        # loudly so a wl-lic build failure cannot hide behind it.
        print(f"WARNING: {dummy} missing (wl-lic build failed?) -- falling "
              f"back to a synthetic dummy license", flush=True)
        dummy.parent.mkdir(parents=True, exist_ok=True)
        make_dummy_license(dummy)
    head_hex = dummy.read_bytes()[:HEAD_LEN].hex()
    nt_path = windows_nt_path(dummy)
    print(f"dummy license: {dummy} head={head_hex} nt={nt_path}", flush=True)

    rows = []
    for label in [t.strip() for t in args.targets.split(",") if t.strip()]:
        entry = by_label.get(label)
        if entry is None or not entry.get("pes"):
            print(f"--- {label}: no PE in the manifest, skipped", flush=True)
            rows.append({"label": label, "error": "no PE in manifest"})
            continue
        target = None
        for pe in entry["pes"]:
            if pe["arch"] == ARCH:
                target = pe
                break
        if target is None:
            print(f"--- {label}: no {ARCH} PE (have "
                  f"{[p['arch'] for p in entry['pes']]}), skipped",
                  flush=True)
            rows.append({"label": label, "error": f"no {ARCH} PE"})
            continue
        exe = (ROOT / target["path"]).resolve()
        workdir = exe.parent
        print(f"\n=== {label}: {exe.name} (v{target['version']}) ===",
              flush=True)
        try:
            run = run_agent(exe, workdir, head_hex, nt_path, args.duration,
                            str(dummy))
            verdict = judge_ci(run, head_hex)
        except Exception as exc:  # noqa: BLE001
            # One sample refusing to inject must not take the whole leg down
            # (it did once: ragexe raised ProcessNotRespondingError and no
            # results were written at all).
            import traceback
            print(f"  runner exception: {exc}", flush=True)
            rows.append({"label": label, "error": str(exc),
                         "traceback": traceback.format_exc()})
            continue
        run["label"] = label
        run["verdict"] = verdict
        rows.append(run)
        print(f"  target: {run['target_stdout'].strip()[:300]}", flush=True)
        for name, check in verdict["checks"].items():
            mark = "PASS" if check["ok"] else "FAIL"
            print(f"  [{mark}] {name}: {check['detail']}", flush=True)
        print(f"  -> {verdict['status']}", flush=True)

    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / f"spike2_ci_{sys.platform}_{ARCH}.json"
    out.write_text(json.dumps(rows, indent=2))
    print(f"\nwrote {out}", flush=True)

    summary = ["## Spike 2 — Stage 0 (license copy location)", ""]
    for row in rows:
        if row.get("error"):
            summary.append(f"- `{row['label']}`: {row['error']}")
            continue
        verdict = row.get("verdict", {})
        summary.append(f"- `{row['label']}`: {verdict.get('status')} "
                       f"({'; '.join(f'{k}={v}' for k, v in verdict.get('checks', {}).items())})")
    summary.append("")
    gh_sum = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_sum:
        with open(gh_sum, "a", encoding="utf-8") as handle:
            handle.write("\n".join(summary) + "\n")

    completed = [r for r in rows
                 if r.get("verdict", {}).get("status") == "stage0-complete"]
    return 0 if completed else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--ci", action="store_true")
    parser.add_argument("--opts", default="0,2")
    parser.add_argument("--duration", type=int, default=150)
    parser.add_argument("--dummy", default="")
    parser.add_argument("--targets", default="")
    args = parser.parse_args()

    RESULTS.mkdir(exist_ok=True)
    if args.local:
        return local_pass([int(o) for o in args.opts.split(",")], args)
    if args.ci:
        return ci_pass(args)
    raise SystemExit("pick --local or --ci")


if __name__ == "__main__":
    sys.exit(main())
