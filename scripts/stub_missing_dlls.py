#!/usr/bin/env python3
"""Build stub DLLs for statically imported but missing DLLs so protected
samples can start at all (fixes 0xC0000135 STATUS_DLL_NOT_FOUND, which is
what made frida injection report ProcessNotRespondingError).

For every target exe matching this interpreter's bitness:
  1. parse its full import table -> {dll: [named imports / ordinals]}
  2. for each imported DLL that is not found on disk (same search logic as
     diagnose_runtime.dll_found): emit stub.c + stub.def exposing exactly
     the symbols the exe imports, compile with MSVC (vcvarsall) into a
     matching-bitness DLL, copy it next to the exe
  3. report per-sample build results

The stubs only have to survive loader-time resolution: unlicense dumps at
the original entry point, before the app ever calls game middleware.

Writes results/stubs_<arch>.json + markdown to GITHUB_STEP_SUMMARY.
Exit 0 always (report-driven; failures stay visible in the table).
"""
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from diagnose_runtime import dll_found  # noqa: E402

_CL_PATH: str | None = None  # absolute cl.exe path resolved by vc_env()


def interpreter_bitness() -> str:
    return "x64" if sys.maxsize > 2**32 else "x86"


def parse_imports_full(path: Path):
    """Return (dll -> list of entries), each entry ('name', str) | ('ord', int)."""
    data = path.read_bytes()
    if data[:2] != b"MZ":
        return {}
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\0\0":
        return {}
    nsec, = struct.unpack_from("<H", data, e + 6)
    opt_off = e + 24
    machine, = struct.unpack_from("<H", data, e + 4)
    is64 = struct.unpack_from("<H", data, opt_off)[0] == 0x20B
    dd_off = opt_off + (112 if is64 else 96)
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

    result = {}
    if not import_rva:
        return result
    off = rva2off(import_rva)
    if off is None:
        return result
    while True:
        ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from(
            "<IIIII", data, off)
        if name_rva == 0:
            break
        no = rva2off(name_rva)
        if no is None:
            break
        dll = data[no:data.index(b"\0", no)].decode("latin1", "replace")
        thunk_rva = ilt_rva or iat_rva
        entries = []
        to = rva2off(thunk_rva)
        if to is not None:
            step = 8 if is64 else 4
            mask = 1 << 63 if is64 else 1 << 31
            for _ in range(1024):
                raw, = struct.unpack_from("<Q" if is64 else "<I", data, to)
                if raw == 0:
                    break
                if raw & mask:
                    entries.append(("ord", raw & 0xFFFF))
                else:
                    ho = rva2off(raw + (2 if is64 else 0))
                    if ho is not None:
                        nm = data[ho:data.index(b"\0", ho)]
                        entries.append(("name", nm.decode("latin1", "replace")))
                to += step
        result.setdefault(dll, []).extend(entries)
        off += 20
    return result, ("x64" if machine == 0x8664 else "x86")


def find_vcvars() -> Path | None:
    pf86 = os.environ.get("ProgramFiles(x86)",
                          r"C:\Program Files (x86)")
    vswhere = Path(pf86) / "Microsoft Visual Studio/Installer/vswhere.exe"
    if vswhere.exists():
        try:
            out = subprocess.run(
                [str(vswhere), "-latest", "-products", "*",
                 "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                 "-property", "installationPath"],
                capture_output=True, text=True, timeout=60).stdout.strip()
            cand = Path(out) / "VC/Auxiliary/Build/vcvarsall.bat"
            if out and cand.exists():
                return cand
        except Exception:  # noqa: BLE001
            pass
    cand = Path(r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
                r"\VC\Auxiliary\Build\vcvarsall.bat")
    return cand if cand.exists() else None


def vc_env(vcvars: Path, arch: str) -> dict | None:
    import shutil
    try:
        r = subprocess.run(
            f'"{vcvars}" {arch} && set', shell=True,
            capture_output=True, timeout=180)
        out = r.stdout.decode("mbcs", errors="replace")
    except Exception as exc:  # noqa: BLE001
        print(f"vc_env: run failed: {exc}", flush=True)
        return None
    env = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if not k or k.startswith("="):  # skip hidden =C:= style keys
                continue
            env[k] = v
    pathkey = next((k for k in env if k.upper() == "PATH"), None)
    if pathkey is None:
        print(f"vc_env: no PATH key (vars={len(env)} rc={r.returncode}) "
              f"stderr={r.stderr[:300]!r}", flush=True)
        return None
    cl = shutil.which("cl", path=env[pathkey])
    if not cl:
        print("vc_env: cl.exe not found in vcvars PATH", flush=True)
        return None
    global _CL_PATH
    _CL_PATH = cl
    return env


def build_stub(dllname: str, entries, workdir: Path, env: dict,
               out_dir: Path) -> str:
    # dedupe entries, keep order
    seen = set()
    uniq = []
    for kind, val in entries:
        key = (kind, val)
        if key not in seen:
            seen.add(key)
            uniq.append((kind, val))

    c_lines = []
    def_lines = ["EXPORTS"]
    for i, (kind, val) in enumerate(uniq):
        fn = f"s{i}"
        c_lines.append(f"int {fn}(void) {{ return 0; }}")
        if kind == "name":
            def_lines.append(f"{val}={fn}")
        else:
            def_lines.append(f"{fn} @{val} NONAME")
    if not uniq:
        return "no entries to stub"

    (workdir / "stub.c").write_text("\n".join(c_lines) + "\n")
    (workdir / "stub.def").write_text("\n".join(def_lines) + "\n")

    cl = _CL_PATH or "cl"
    cmd = [cl, "/nologo", "/LD", "/MT", "/O2", "stub.c", "/link",
           "/DEF:stub.def", f"/OUT:{dllname}"]
    try:
        r = subprocess.run(cmd, cwd=str(workdir), env=env,
                           capture_output=True, text=True, timeout=300)
    except Exception as exc:  # noqa: BLE001
        return f"cl failed to run ({cl}): {exc}"
    if r.returncode != 0 or not (workdir / dllname).exists():
        tail = (r.stderr or r.stdout or "")[-300:].replace("\n", " ")
        return f"cl rc={r.returncode}: {tail}"
    dest = out_dir / dllname
    dest.write_bytes((workdir / dllname).read_bytes())
    return f"built ({len(uniq)} exports)"


def main() -> int:
    bitness = interpreter_bitness()
    vcvars = find_vcvars()
    if not vcvars:
        print("FATAL: vcvarsall.bat not found (vswhere + Enterprise fallback)",
              flush=True)
    arch = "x64" if bitness == "x64" else "x86"
    env = vc_env(vcvars, arch) if vcvars else None
    if env:
        print(f"MSVC env ready ({vcvars}, {arch})", flush=True)
    else:
        print("FATAL: MSVC environment setup failed (see vc_env diagnostics)",
              flush=True)

    manifest = json.loads((RESULTS / "manifest.json").read_text())
    build_root = ROOT / "results" / "stubs_build"
    build_root.mkdir(parents=True, exist_ok=True)

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
        parsed = parse_imports_full(exe)
        if isinstance(parsed, tuple):
            imports, pe_arch = parsed
        else:
            continue
        dll_missing = {d: e for d, e in imports.items()
                       if not dll_found(d, exe.parent)}
        if not dll_missing:
            continue
        results = {}
        for dll, ents in dll_missing.items():
            if not env:
                results[dll] = "no MSVC env"
                continue
            wd = build_root / f"{entry['label']}_{dll}"
            wd.mkdir(parents=True, exist_ok=True)
            # compile with arch matching the PE, not this interpreter
            dll_arch = "x64" if pe_arch == "x64" else "x86"
            denv = env
            if dll_arch != arch:
                denv = vc_env(vcvars, dll_arch) or env
            res = build_stub(dll, ents, wd, denv, exe.parent)
            results[dll] = res
            print(f"[{entry['label']}] {dll}: {res}", flush=True)
        rows.append({"label": entry["label"], "exe": exe.name,
                     "stubs": results})

    report = {"bitness": bitness, "rows": rows}
    (RESULTS / f"stubs_{bitness}.json").write_text(json.dumps(report,
                                                              indent=2))
    md = [f"## Stub DLL builds (python {bitness})", "",
          "| sample | dll | result |", "|---|---|---|"]
    for r in rows:
        for dll, res in r["stubs"].items():
            md.append(f"| {r['label']} | {dll} | {res} |")
    summary = "\n".join(md) + "\n"
    print(summary, flush=True)
    gh_sum = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_sum:
        with open(gh_sum, "a", encoding="utf-8") as f:
            f.write(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
