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
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from diagnose_runtime import dll_found  # noqa: E402

# A believable imported DLL filename: short, ASCII, no path separators and with
# a PE module extension. Anything else is packer garbage in the import area.
PLAUSIBLE_DLL = re.compile(
    r"^[\w .()+@,-]{1,64}\.(dll|ocx|drv|sys|cpl|exe)$", re.IGNORECASE)




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

    def thunk_entries(rva):
        """Parse an array of thunks -> [('name', str) | ('ord', int), ...]."""
        out = []
        to = rva2off(rva) if rva else None
        if to is None:
            return out
        step = 8 if is64 else 4
        fmt = "<Q" if is64 else "<I"
        mask = 1 << 63 if is64 else 1 << 31
        for _ in range(2048):
            if to + step > len(data):
                break
            raw, = struct.unpack_from(fmt, data, to)
            if raw == 0:
                break
            if raw & mask:
                out.append(("ord", raw & 0xFFFF))
            else:
                # IMAGE_IMPORT_BY_NAME is {WORD Hint; CHAR Name[]} in both
                # PE32 and PE32+, so the string starts 2 bytes past the RVA.
                ho = rva2off(raw)
                if ho is not None and ho + 2 < len(data):
                    end = data.find(b"\0", ho + 2)
                    if end == -1:
                        break
                    out.append(("name", data[ho + 2:end]
                                .decode("latin1", "replace")))
            to += step
        return out

    def delay_import_dlls():
        """DLLs from the delay-import directory (index 13).

        tera65-style samples load game middleware lazily; those names never
        appear in the normal import table, so without this the stub set is
        incomplete and the loader still fails with STATUS_DLL_NOT_FOUND.
        """
        try:
            delay_rva = struct.unpack_from("<I", data, dd_off + 13 * 8)[0]
        except struct.error:
            return []
        if not delay_rva:
            return []
        do = rva2off(delay_rva)
        if do is None:
            return []
        image_base = struct.unpack_from(
            "<Q" if is64 else "<I", data,
            opt_off + (24 if is64 else 28))[0]
        out = []
        for _ in range(256):
            if do + 32 > len(data):
                break
            attrs, name_va, _, iat_rva, int_rva = struct.unpack_from(
                "<IIIII", data, do)
            if name_va == 0 and attrs == 0:
                break
            # bit 0 clear means the fields are VAs, not RVAs
            norm = (lambda v: v - image_base) if not (attrs & 1) else (lambda v: v)
            no = rva2off(norm(name_va))
            if no is not None:
                end = data.find(b"\0", no)
                if end == -1:
                    # Some packers leave the name unterminated at the section
                    # boundary; fall back to a bounded slice.
                    end = min(no + 128, len(data))
                dll = data[no:end].decode("latin1", "replace")
                out.append((dll, thunk_entries(norm(int_rva)) +
                            thunk_entries(norm(iat_rva))))
            do += 32
        return out

    result = {}
    delay_seen = set()
    if not import_rva:
        d = dict(delay_import_dlls())
        delay_seen = set(d)
        return d, ("x64" if machine == 0x8664 else "x86"), delay_seen
    off = rva2off(import_rva)
    if off is None:
        d = dict(delay_import_dlls())
        delay_seen = set(d)
        return d, ("x64" if machine == 0x8664 else "x86"), delay_seen
    while True:
        ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from(
            "<IIIII", data, off)
        if name_rva == 0 and ilt_rva == 0 and iat_rva == 0:
            break
        no = rva2off(name_rva)
        if no is None:
            break
        dll_end = data.find(b"\0", no)
        if dll_end == -1:
            break
        dll = data[no:dll_end].decode("latin1", "replace")
        # Packers routinely wipe OriginalFirstThunk, and on disk the IAT holds
        # unresolved hints -- so union both arrays rather than trusting either.
        entries = thunk_entries(ilt_rva) + thunk_entries(iat_rva)
        result.setdefault(dll, []).extend(entries)
        off += 20
    for dll, entries in delay_import_dlls():
        result.setdefault(dll, []).extend(entries)
        delay_seen.add(dll)
    return result, ("x64" if machine == 0x8664 else "x86"), delay_seen


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


def vc_env(vcvars: Path, arch: str):
    """Return (env, cl_path) for the given toolchain arch.

    Windows CreateProcess resolves the program name against the *parent*
    process PATH, so passing env with a vcvars PATH is not enough to run
    `cl` -- it must be invoked by absolute path.
    """
    import shutil
    try:
        r = subprocess.run(
            f'"{vcvars}" {arch} && set', shell=True,
            capture_output=True, timeout=180)
        out = r.stdout.decode("mbcs", errors="replace")
    except Exception as exc:  # noqa: BLE001
        print(f"vc_env({arch}): run failed: {exc}", flush=True)
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
        print(f"vc_env({arch}): no PATH key (vars={len(env)} rc={r.returncode}) "
              f"stderr={r.stderr[:300]!r}", flush=True)
        return None
    cl = shutil.which("cl", path=env[pathkey])
    if not cl:
        print(f"vc_env({arch}): cl.exe not found in vcvars PATH", flush=True)
        return None
    return env, cl


def parse_exports(path: Path):
    """Export names of a built PE, so we can verify the stub really publishes
    everything the sample imports (a silently short export table shows up on
    Windows as STATUS_ENTRYPOINT_NOT_FOUND, not as a build error)."""
    data = path.read_bytes()
    try:
        e = struct.unpack_from("<I", data, 0x3C)[0]
        opt_off = e + 24
        is64 = struct.unpack_from("<H", data, opt_off)[0] == 0x20B
        dd_off = opt_off + (112 if is64 else 96)
        nsec = struct.unpack_from("<H", data, e + 6)[0]
        sec_off = opt_off + struct.unpack_from("<H", data, e + 20)[0]
        secs = []
        for i in range(nsec):
            o = sec_off + i * 40
            vsize, va, rawsz, rawptr = struct.unpack_from("<IIII", data, o + 8)
            secs.append((va, vsize, rawptr, rawsz))
        exp_rva = struct.unpack_from("<I", data, dd_off)[0]
        if not exp_rva:
            return []

        def rva2off(rva):
            for va, vsize, rawptr, rawsz in secs:
                if va <= rva < va + max(vsize, rawsz):
                    return rawptr + (rva - va)
            return None

        o = rva2off(exp_rva)
        nnames = struct.unpack_from("<I", data, o + 24)[0]
        names_rva = struct.unpack_from("<I", data, o + 32)[0]
        nt = rva2off(names_rva)
        if nt is None:
            return []
        out = []
        for i in range(nnames):
            nr = struct.unpack_from("<I", data, nt + 4 * i)[0]
            no = rva2off(nr)
            if no is None:
                continue
            end = data.find(b"\0", no)
            if end == -1:
                continue
            out.append(data[no:end].decode("latin1", "replace"))
        return out
    except Exception:  # noqa: BLE001
        return []


def build_stub(dllname: str, entries, workdir: Path, env: dict,
               out_dir: Path, cl: str = "cl") -> str:
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
        if kind == "ord":
            def_lines.append(f"{fn} @{val} NONAME")
        elif any(c in val for c in ' ="<>'):
            # Neither a bare .def name nor /EXPORT can express these; give the
            # stub an ordinal so the image still loads.
            def_lines.append(f"{fn} @{1000 + i} NONAME")
        elif "@" in val:
            # A bare `name=internal` line makes the linker read '@' as the
            # start of an ordinal suffix, so stdcall-decorated names such as
            # `_BinkGoto@12` are quoted -- the .def grammar's own escape for
            # names containing characters it would otherwise interpret.
            def_lines.append(f'"{val}"={fn}')
        else:
            def_lines.append(f"{val}={fn}")
    # A DLL with an empty export table is still a loadable image, which is
    # what ordinal-only delay imports need.
    (workdir / "stub.c").write_text("\n".join(
        c_lines +
        ["__declspec(dllexport) int __stub_anchor(void) { return 0; }"]) + "\n")
    (workdir / "stub.def").write_text("\n".join(def_lines) + "\n")

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

    want = {v for k, v in uniq if k == "name"}
    got = set(parse_exports(dest))
    missing = sorted(want - got)
    if missing:
        return (f"built but MISSING {len(missing)} export(s): "
                f"{', '.join(missing[:5])}")
    return (f"built ({len(uniq)} entries, {len(want)} named exports all "
            f"resolved)")


def main() -> int:
    bitness = interpreter_bitness()
    vcvars = find_vcvars()
    if not vcvars:
        print("FATAL: vcvarsall.bat not found (vswhere + Enterprise fallback)",
              flush=True)
    arch = "x64" if bitness == "x64" else "x86"
    setup = vc_env(vcvars, arch) if vcvars else None
    if setup:
        env, cl = setup
        print(f"MSVC env ready ({vcvars}, {arch}, cl={cl})", flush=True)
    else:
        env, cl = None, "cl"
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
        try:
            parsed = parse_imports_full(exe)
        except Exception as exc:  # noqa: BLE001
            print(f"[{entry['label']}] import parse failed: {exc}", flush=True)
            continue
        if isinstance(parsed, tuple) and len(parsed) == 3:
            imports, pe_arch, delay_seen = parsed
        else:
            continue
        dll_missing = {d: e for d, e in imports.items()
                       if not dll_found(d, exe.parent)}
        # Packed samples leave garbage in the import area; a "DLL name" that
        # is not a plausible filename must not reach the filesystem.
        junk = sorted(d for d in dll_missing if not PLAUSIBLE_DLL.match(d))
        for d in junk:
            print(f"[{entry['label']}] ignoring junk import name: "
                  f"{d!r}", flush=True)
            dll_missing.pop(d)
        if not dll_missing:
            continue
        results = {}
        for dll, ents in dll_missing.items():
            if not env:
                results[dll] = "no MSVC env"
                continue
            wd = build_root / f"{entry['label']}_{dll}"
            wd.mkdir(parents=True, exist_ok=True)
            # compile with the toolchain matching the PE, not this interpreter
            dll_arch = "x64" if pe_arch == "x64" else "x86"
            denv, dcl = env, cl
            if dll_arch != arch and vcvars:
                alt = vc_env(vcvars, dll_arch)
                if alt:
                    denv, dcl = alt
            res = build_stub(dll, ents, wd, denv, exe.parent, dcl)
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
