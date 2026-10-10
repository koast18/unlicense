#!/usr/bin/env python3
"""Prepare every sample listed in the given manifest(s) and emit
results/manifest.json for run_unpack.py / run_spike2.py.

A manifest line is `LABEL<TAB>SOURCE<TAB>NOTES`, where SOURCE is either an
http(s) URL (downloaded here) or a path relative to the repo root (a file the
workflow already staged, e.g. an asset pulled from a private release with the
`gh` CLI -- `gh` is used for those because it handles GitHub's cross-host
redirect without leaking the Authorization header to the storage backend).

Local sources are copied into samples/extracted/<label>/, together with every
file staged in samples/dl/ (sibling DLLs and a license file), so a sample that
needs its own runtime DLLs can actually start. `pes` always lists only the
entry's own PE -- the companions are on disk, not extra targets.
"""
import argparse
import json
import os
import shutil
import struct
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
RESULTS = ROOT / "results"
DEFAULT_LIST = ROOT / "tests" / "samples.list"
COMPANION_DIR = SAMPLES / "dl"

UA = {"User-Agent": "Mozilla/5.0 (X64; Windows NT 10.0; Win64; x64) sample-fetch"}


def download(url: str, dest: Path) -> bool:
    if dest.exists() and dest.stat().st_size > 1024:
        return True
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as out:
            shutil.copyfileobj(resp, out)
        return dest.stat().st_size > 1024
    except Exception as exc:  # noqa: BLE001
        print(f"  download failed: {exc}")
        return False


def pe_arch(path: Path) -> str:
    try:
        data = path.read_bytes()
        if data[:2] != b"MZ":
            return ""
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return ""
        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        return {0x14C: "x86", 0x8664: "x64"}.get(machine, "")
    except Exception:  # noqa: BLE001
        return ""


def companion_files() -> list:
    if not COMPANION_DIR.is_dir():
        return []
    return [p for p in sorted(COMPANION_DIR.iterdir()) if p.is_file()]


def stage_local(source_rel: str, label: str):
    """Copy a repo-relative source into samples/extracted/<label>/ and return
    the copy. Missing source -> None (reported as SKIP_NODL by the caller)."""
    src = (ROOT / source_rel).resolve()
    if not src.is_file():
        return None
    out_dir = SAMPLES / "extracted" / label
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / src.name
    shutil.copy(src, dest)
    for extra in companion_files():
        if extra.name != dest.name:
            shutil.copy(extra, out_dir / extra.name)
    return dest


def extract_pes(archive: Path, label: str):
    """Unzip archive (incl. one level of inner zips) and return PEs found."""
    out_dir = SAMPLES / "extracted" / label
    out_dir.mkdir(parents=True, exist_ok=True)
    found = []
    try:
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(out_dir)
    except zipfile.BadZipFile:
        return found
    for inner in list(out_dir.rglob("*.zip")):
        try:
            with zipfile.ZipFile(inner) as zf:
                zf.extractall(inner.parent)
        except zipfile.BadZipFile:
            pass
    for cand in out_dir.rglob("*"):
        if cand.suffix.lower() in (".exe", ".dll") and cand.is_file():
            if pe_arch(cand):
                found.append(cand)
    return found


def list_files(explicit: list) -> list:
    if explicit:
        return [Path(p) for p in explicit]
    env = os.environ.get("SAMPLES_LISTS", "").strip()
    if env:
        parts = [p for p in env.replace(",", ":").split(":") if p.strip()]
        return [(ROOT / p.strip()) if not Path(p).is_absolute() else Path(p)
                for p in parts]
    return [DEFAULT_LIST]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="append", default=[],
                        help="manifest to read (repeatable); default: "
                             "SAMPLES_LISTS env or tests/samples.list")
    args = parser.parse_args()

    SAMPLES.mkdir(exist_ok=True)
    RESULTS.mkdir(exist_ok=True)

    from unlicense.version_detection import detect_winlicense_version

    lines = []
    for path in list_files(args.list):
        if not path.is_file():
            print(f"manifest missing: {path}")
            continue
        for line in path.read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                lines.append((path.name, line))

    manifest = []
    for source_file, line in lines:
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        label, source = parts[0], parts[1]
        notes = parts[2] if len(parts) > 2 else ""

        remote = source.startswith(("http://", "https://"))
        is_zip = source.lower().endswith(".zip")
        if remote:
            dest = SAMPLES / (f"{label}.zip" if is_zip
                              else f"{label}{Path(source).suffix or '.exe'}")
            ok = download(source, dest)
            # a "downloaded" file that is not actually a PE (HTML error page)
            if ok and not is_zip and not pe_arch(dest):
                print(f"{label:16} SKIP_NOPE  (not a PE: {dest.stat().st_size}B)")
                manifest.append({"label": label, "notes": notes,
                                 "downloaded": False, "pes": [],
                                 "status": "SKIP_NOPE"})
                continue
        else:
            dest = stage_local(source, label)
            ok = dest is not None
            if not ok:
                print(f"{label:16} SKIP_NODL  (local source missing: {source})")

        entry = {"label": label, "notes": notes, "list": source_file,
                 "downloaded": ok, "pes": [],
                 "status": "OK" if ok else "SKIP_NODL"}
        if ok:
            assert dest is not None
            pes = extract_pes(dest, label) if is_zip else [dest]
            if not pes:
                entry["status"] = "SKIP_NOPE"
            for pe in pes:
                entry["pes"].append({
                    "path": str(pe.relative_to(ROOT)),
                    "arch": pe_arch(pe),
                    "version": detect_winlicense_version(str(pe)),
                    "size": pe.stat().st_size,
                })
        print(f"{label:16} {entry['status']:10} pes={len(entry['pes'])} {notes}")
        manifest.append(entry)

    (RESULTS / "manifest.json").write_text(json.dumps(manifest, indent=2))
    total = len(manifest)
    dl = sum(1 for e in manifest if e["downloaded"])
    pe_n = sum(len(e["pes"]) for e in manifest)
    print(f"\nmanifest: {total} targets, {dl} downloaded, {pe_n} PEs")
    return 0 if pe_n else 1


if __name__ == "__main__":
    sys.exit(main())
