#!/usr/bin/env python3
"""Build whatlicense's `wl-lic` (the license/dummy-license builder) and run it
to produce the dummy license Stage 0 needs.

wl-lic is a standalone MSVC console project (8 C++ files + libtommath + a
sha1) that lives in the whatlicense checkout — it is NOT part of the unlicense
fork, so its path is passed in (or taken from the WLIC_DIR environment
variable / a sibling ../whatlicense directory).

Two compilers are attempted in order, and which one worked is reported:
  1. mingw-w64 (already installed for the stub builder) — no environment hunt
  2. MSVC via vcvarsall.bat — the project's native toolchain

Output: results/wl_lic_build.json (compiler, status, dummy path, head bytes).
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
OUT = RESULTS / "spike2_dummy"

sys.path.insert(0, str(ROOT / "scripts"))

ARCH = "x64" if sys.maxsize > 2 ** 32 else "x86"


def wlic_dir() -> Path:
    for candidate in [os.environ.get("WLIC_DIR"),
                      ROOT.parent / "whatlicense",
                      ROOT / "whatlicense"]:
        if candidate and (Path(candidate) / "wl-lic" / "main.cpp").exists():
            return Path(candidate)
    raise SystemExit("whatlicense checkout not found (set WLIC_DIR)")


def sources(wlic: Path):
    cpp = sorted((wlic / "wl-lic").glob("*.cpp"))
    cpp += sorted((wlic / "wl-lic" / "rsa").glob("*.cpp"))
    c = sorted((wlic / "wl-lic" / "rsa" / "libtommath").glob("*.c"))
    c += sorted((wlic / "wl-lic" / "rsa" / "sha1").glob("*.c"))
    includes = [wlic / "wl-lic", wlic / "wl-lic" / "rsa",
                wlic / "wl-lic" / "rsa" / "libtommath",
                wlic / "wl-lic" / "rsa" / "sha1"]
    return cpp, c, includes


def build(exe: Path) -> dict:
    """Build wl-lic with the shared toolchain helper (MSVC first: Visual
    Studio is part of the runner image, while the mingw download goes through
    a rate-limited API)."""
    import toolchain  # noqa: E402

    wlic = wlic_dir()
    cpp, c, includes = sources(wlic)
    result = toolchain.compile_cpp(cpp + c, exe, includes,
                                  RESULTS / "wl_lic_obj")
    print(f"toolchain: {result.get('compiler')} "
          f"objects={result.get('objects')} ok={result['ok']}", flush=True)
    for attempt in result.get("attempts", []):
        print(f"  {attempt}", flush=True)
    return result


def main() -> int:
    wlic = wlic_dir()
    RESULTS.mkdir(exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    exe = RESULTS / ("wl-lic.exe" if sys.platform == "win32" else "wl-lic")
    print(f"whatlicense: {wlic}", flush=True)

    if sys.platform != "win32":
        build_result = {"ok": False, "compiler": None,
                        "attempts": [{"compiler": "none",
                                      "status": "not Windows"}]}
    else:
        build_result = build(exe)
    attempts = build_result.get("attempts", [])

    info = {"whatlicense": str(wlic), "attempts": attempts,
            "compiler": build_result.get("compiler"),
            "exe": str(exe) if exe.exists() else None}
    if exe.exists():
        dummy = OUT / "regkey.dat"
        rsa = OUT / "regkey.rsa"
        proc = subprocess.run([str(exe), "-d", str(dummy), "-r", str(rsa)],
                              capture_output=True, text=True, cwd=str(OUT))
        info["wl_lic_rc"] = proc.returncode
        info["wl_lic_stdout"] = (proc.stdout or "")[-1500:]
        info["wl_lic_stderr"] = (proc.stderr or "")[-500:]
        if dummy.exists():
            info["dummy"] = str(dummy)
            info["dummy_size"] = dummy.stat().st_size
            info["head_hex"] = dummy.read_bytes()[:8].hex()
        if rsa.exists():
            info["rsa"] = str(rsa)
            info["rsa_size"] = rsa.stat().st_size
    info["status"] = ("ok" if info.get("head_hex")
                      else "failed to produce a dummy license")
    print(f"wl-lic: {info['status']}", flush=True)
    for key in ("dummy", "dummy_size", "head_hex", "rsa_size", "wl_lic_rc"):
        if key in info:
            print(f"  {key}: {info[key]}", flush=True)
    (RESULTS / "wl_lic_build.json").write_text(json.dumps(info, indent=2))

    gh_sum = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_sum:
        with open(gh_sum, "a", encoding="utf-8") as handle:
            handle.write(f"## wl-lic build\n\n{info['status']}\n\n")
            for attempt in attempts:
                handle.write(f"- {attempt.get('compiler')}: "
                             f"{attempt.get('status') or attempt}\n")
            handle.write("\n")
    return 0 if info["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
