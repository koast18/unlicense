#!/usr/bin/env python3
"""Fetch a mingw-w64 toolchain that can target `arch` (x86 or x64).

Why not the `mingw` chocolatey package: it installs an x86_64-only mingw-w64,
so the x86 matrix job has no i686 cross compiler and silently falls back to
MSVC, whose linker drops stdcall-decorated export names such as
`_BinkGoto@12` (see build_stub). The winlibs builds ship one archive per
target, so we pick the asset matching the bitness we need.

Installed under tools/mingw/<arch>/ and put on PATH for the current process;
find_mingw() looks there first.

Writes results/mingw_install.json. Exit 0 even on failure (the caller falls
back to MSVC), but the reason is recorded and printed.
"""
import json
import os
import re
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools" / "mingw"
RESULTS = ROOT / "results"

RELEASES_API = ("https://api.github.com/repos/brechtsanders/winlibs_mingw/"
                "releases?per_page=5")
UA = {"User-Agent": "unlicense-ci-mingw-fetch"}


def interpreter_bitness() -> str:
    return "x64" if sys.maxsize > 2**32 else "x86"


def fetch_json(url: str):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def pick_asset(releases, arch: str):
    """Newest non-rc release asset that targets `arch`."""
    token = "i686" if arch == "x86" else "x86_64"
    for rel in releases:
        if rel.get("draft") or rel.get("prerelease"):
            continue
        for asset in rel.get("assets", []):
            name = asset.get("name", "")
            if not name.endswith(".zip"):
                continue
            if token not in name:
                continue
            # posix + ucrt runtime variants build fine on the runner
            if "posix" in name and "ucrt" in name and "posix-seh" in name:
                return name, asset["browser_download_url"]
    return None, None


def install(arch: str) -> dict:
    dest = TOOLS / arch
    info = {"arch": arch, "dest": str(dest)}
    marker = dest / ".installed"
    if marker.exists():
        info["status"] = "already installed"
        return info
    dest.mkdir(parents=True, exist_ok=True)
    try:
        releases = fetch_json(RELEASES_API)
    except Exception as exc:  # noqa: BLE001
        info["status"] = f"release lookup failed: {exc}"
        return info
    name, url = pick_asset(releases, arch)
    if not url:
        info["status"] = "no matching winlibs asset found"
        return info
    info["asset"] = name
    info["url"] = url
    archive = dest / "toolchain.zip"
    try:
        req = urllib.request.Request(str(url), headers=UA)
        with urllib.request.urlopen(req, timeout=600) as resp, \
                open(archive, "wb") as out:
            shutil.copyfileobj(resp, out)
    except Exception as exc:  # noqa: BLE001
        info["status"] = f"download failed: {exc}"
        return info
    try:
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
    except Exception as exc:  # noqa: BLE001
        info["status"] = f"extract failed: {exc}"
        return info
    archive.unlink(missing_ok=True)
    # winlibs archives contain mingw64/ (x86_64) or mingw32/ (i686)
    for sub in ("mingw64", "mingw32"):
        if (dest / sub / "bin").is_dir():
            info["bindir"] = str(dest / sub / "bin")
            break
    if "bindir" not in info:
        info["status"] = "extracted, but no mingw64/mingw32/bin found"
        return info
    exe = "i686-w64-mingw32-gcc.exe" if arch == "x86" \
        else "x86_64-w64-mingw32-gcc.exe"
    compiler = Path(info["bindir"]) / exe
    info["compiler"] = str(compiler)
    info["status"] = ("ok" if compiler.exists()
                      else f"extracted but {exe} missing")
    if compiler.exists():
        marker.write_text(url, encoding="utf-8")
        os.environ["PATH"] = info["bindir"] + os.pathsep + os.environ["PATH"]
    return info


def main() -> int:
    arch = interpreter_bitness()
    info = install(arch)
    print(f"mingw[{arch}]: {info['status']}", flush=True)
    for k in ("asset", "bindir", "compiler"):
        if k in info:
            print(f"  {k}: {info[k]}", flush=True)
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "mingw_install.json").write_text(json.dumps(info, indent=2))
    gh_sum = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_sum:
        with open(gh_sum, "a", encoding="utf-8") as f:
            f.write(f"## mingw-w64 toolchain\n\n{info['status']}\n\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())