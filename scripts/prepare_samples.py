#!/usr/bin/env python3
"""Download all samples listed in tests/samples.list, extract archives,
detect packer version/arch, and emit results/manifest.json for run_unpack.py.
"""
import json
import shutil
import struct
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
RESULTS = ROOT / "results"
LIST_FILE = ROOT / "tests" / "samples.list"

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


def main() -> int:
    SAMPLES.mkdir(exist_ok=True)
    RESULTS.mkdir(exist_ok=True)

    from unlicense.version_detection import detect_winlicense_version

    manifest = []
    for line in LIST_FILE.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        label, url = parts[0], parts[1]
        notes = parts[2] if len(parts) > 2 else ""

        is_zip = ".zip" in url.lower()
        dest = SAMPLES / (f"{label}.zip" if is_zip else f"{label}.exe")
        ok = download(url, dest)
        # a "downloaded" exe that is not actually a PE (HTML error page etc.)
        if ok and not is_zip and not pe_arch(dest):
            print(f"{label:16} SKIP_NOPE  (not a PE: {dest.stat().st_size}B)")
            manifest.append({"label": label, "notes": notes, "downloaded": False,
                             "pes": [], "status": "SKIP_NOPE"})
            continue
        entry = {"label": label, "notes": notes, "downloaded": ok,
                 "pes": [], "status": "OK" if ok else "SKIP_NODL"}
        if ok:
            pes = [dest] if dest.suffix == ".exe" else extract_pes(dest, label)
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
