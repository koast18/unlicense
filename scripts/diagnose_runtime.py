#!/usr/bin/env python3
"""For each sample whose bitness matches, statically list imported DLLs and
report which ones are NOT found in the usual search paths (exe dir,
System32, SysWOW64, Windows dir). That pinpoints missing runtimes behind
0xC0000135 (STATUS_DLL_NOT_FOUND) startup failures.

Writes results/dll_report.json + markdown table to GITHUB_STEP_SUMMARY.
"""
import json
import os
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"


def interpreter_bitness() -> str:
    return "x64" if sys.maxsize > 2**32 else "x86"


def import_dlls(path: Path) -> list[str]:
    data = path.read_bytes()
    if data[:2] != b"MZ":
        return []
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\0\0":
        return []
    nsec, = struct.unpack_from("<H", data, e + 6)
    opt_off = e + 24
    pe32p = struct.unpack_from("<H", data, opt_off)[0] == 0x20B
    dd_off = opt_off + (112 if pe32p else 96)
    import_rva, = struct.unpack_from("<I", data, dd_off + 8)
    sec_off = opt_off + struct.unpack_from("<H", data, e + 20)[0]
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        vsize, va, rawsz, rawptr = struct.unpack_from("<IIII", data, o + 8)
        secs.append((va, vsize, rawptr, rawsz))

    def rva2off(rva):
        for va, vsize, rawptr, rawsz in secs:
            if va <= rva < va + max(vsize, rawsz):
                return rawptr + (rva - va)
        return None

    dlls = []
    if not import_rva:
        return dlls
    off = rva2off(import_rva)
    if off is None:
        return dlls
    while len(dlls) < 120:
        name_rva, = struct.unpack_from("<I", data, off + 12)
        if name_rva == 0:
            break
        no = rva2off(name_rva)
        if no is None:
            break
        end = data.index(b"\0", no)
        dlls.append(data[no:end].decode("latin1", "replace"))
        off += 20
    return dlls


def dll_found(dll: str, exe_dir: Path) -> bool:
    name = dll.lower()
    # already beside the exe?
    if (exe_dir / dll).exists() or (exe_dir / name).exists():
        return True
    windir = os.environ.get("WINDIR", r"C:\Windows")
    candidates = [
        Path(windir) / "System32" / name,
        Path(windir) / "SysWOW64" / name,
        Path(windir) / name,
        Path(windir) / "WinSxS",  # presence of WinSxS dir handled below
    ]
    for c in candidates[:3]:
        if c.exists():
            return True
    # system DLLs that always exist on modern Windows even if renamed check
    # (api-set resolution): api-ms-*, ext-ms-* resolve dynamically
    if name.startswith(("api-ms-", "ext-ms-")):
        return True
    return False


def main() -> int:
    manifest = json.loads((RESULTS / "manifest.json").read_text())
    bitness = interpreter_bitness()
    rows = []
    for entry in manifest:
        if not entry["downloaded"] or not entry["pes"]:
            continue
        exes = [p for p in entry["pes"]
                if p["path"].lower().endswith(".exe")
                and p["arch"] == bitness
                and p.get("version") is not None]
        if not exes:
            continue
        exe = ROOT / exes[0]["path"]
        dlls = import_dlls(exe)
        missing = sorted({d for d in dlls
                          if not dll_found(d, exe.parent)})
        rows.append({"label": entry["label"], "exe": exe.name,
                     "imports": len(dlls), "missing": missing})
        print(f"{entry['label']:16} imports={len(dlls):3} "
              f"missing={missing}", flush=True)

    all_missing = sorted({d for r in rows for d in r["missing"]})
    report = {"bitness": bitness, "rows": rows, "all_missing": all_missing}
    (RESULTS / f"dll_{bitness}.json").write_text(json.dumps(report, indent=2))

    md = [f"## Missing DLL report (python {bitness})", "",
          "| sample | imports | missing |", "|---|---|---|"]
    for r in rows:
        md.append(f"| {r['label']} | {r['imports']} | "
                  f"{', '.join(r['missing']) or '-'} |")
    md.append("")
    md.append(f"**union of missing: {', '.join(all_missing) or 'none'}**")
    summary = "\n".join(md) + "\n"
    print(summary, flush=True)
    gh_sum = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_sum:
        with open(gh_sum, "a", encoding="utf-8") as f:
            f.write(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
