#!/usr/bin/env python3
"""Static classification of sample PEs: packer version (Themida/WL 2.x|3.x) and arch.

Reads tests/samples.list (LABEL<TAB>URL<TAB>NOTES), scans samples_dir for
matching files (zip extracted alongside), prints a table and fails if NO sample
could be classified at all (that means the pipeline itself is broken).
"""
import io
import struct
import sys
import zipfile
from pathlib import Path

from unlicense.version_detection import detect_winlicense_version

SAMPLES_LIST = Path("tests/samples.list")
SAMPLES_DIR = Path("samples")


def pe_arch(path: Path) -> str:
    try:
        data = path.read_bytes()
        if data[:2] != b"MZ":
            return "not-PE"
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return "not-PE"
        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        return {0x14C: "x86", 0x8664: "x64"}.get(machine, f"machine=0x{machine:x}")
    except Exception as exc:  # noqa: BLE001 - classification must not crash CI
        return f"error:{exc}"


def find_pe(label: str) -> Path:
    """Locate the PE for a label: direct exe, or the first PE inside its zip."""
    for cand in sorted(SAMPLES_DIR.glob(f"{label}*")):
        if cand.suffix.lower() in (".exe", ".dll"):
            return cand
        if cand.suffix.lower() in (".zip", ".7z", ".rar"):
            if cand.suffix.lower() != ".zip":
                continue
            try:
                with zipfile.ZipFile(cand) as zf:
                    for name in zf.namelist():
                        if name.lower().endswith((".exe", ".dll")):
                            out = SAMPLES_DIR / f"{label}_{Path(name).name}"
                            if not out.exists():
                                out.write_bytes(zf.read(name))
                            return out
            except zipfile.BadZipFile:
                continue
    return Path()


def main() -> int:
    SAMPLES_DIR.mkdir(exist_ok=True)
    classified = 0
    total = 0
    for line in SAMPLES_LIST.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        label, _url, notes = (line.split("\t") + ["", "", ""])[:3]
        total += 1
        pe = find_pe(label)
        if not pe or not pe.exists():
            print(f"{label:14} MISSING   ({notes})")
            continue
        ver = detect_winlicense_version(str(pe))
        arch = pe_arch(pe)
        size = pe.stat().st_size
        print(f"{label:14} v{ver} {arch:4} {size:>9}B  {pe.name}")
        classified += 1

    print(f"\nclassified {classified}/{total}")
    if classified == 0:
        print("ERROR: no sample could be classified — pipeline broken")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
