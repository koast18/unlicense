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


def find_mingw() -> tuple:
    import install_mingw  # noqa: E402

    info = install_mingw.install(ARCH)
    exe = ("i686-w64-mingw32-gcc.exe" if ARCH == "x86"
           else "x86_64-w64-mingw32-gcc.exe")
    gxx = exe.replace("-gcc.exe", "-g++.exe")
    for candidate in sorted((ROOT / "tools" / "mingw" / ARCH)
                            .glob("*/bin/" + exe)):
        return str(candidate), str(candidate.parent / gxx)
    if info.get("compiler") and Path(info["compiler"]).exists():
        return info["compiler"], str(Path(info["compiler"]).parent / gxx)
    found = shutil.which(exe)
    if found:
        return found, str(Path(found).parent / gxx)
    return None, None


def build_mingw(wlic: Path, out: Path, work: Path) -> dict:
    gcc, gxx = find_mingw()
    if gcc is None or not Path(gxx).exists():
        return {"compiler": "mingw", "status": "not available"}
    cpp, c, includes = sources(wlic)
    inc = [f"-I{p}" for p in includes]
    # wl-lic was written against MSVC's headers, which include the C string
    # functions transitively; gcc needs them spelled out (crypt.cpp uses
    # strlen without including <cstring>). Force the common ones in rather
    # than patching the author's sources.
    forced = ["-include", "cstring", "-include", "cstdio",
              "-include", "cstdlib", "-include", "cstdint",
              "-include", "string", "-include", "cmath"]
    work.mkdir(parents=True, exist_ok=True)
    objects = []
    for source in c:
        obj = work / (source.stem + ".o")
        proc = subprocess.run([gcc, "-c", "-O1", "-w", *inc, "-o", str(obj),
                               str(source)], capture_output=True, text=True)
        if proc.returncode != 0:
            return {"compiler": "mingw", "status": "C compile failed",
                    "file": source.name, "stderr": proc.stderr[-800:]}
        objects.append(str(obj))
    for source in cpp:
        obj = work / (source.stem + ".o")
        proc = subprocess.run([gxx, "-c", "-O1", "-w", "-std=c++17", *forced,
                               *inc, "-o", str(obj), str(source)],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            return {"compiler": "mingw", "status": "C++ compile failed",
                    "file": source.name, "stderr": proc.stderr[-800:]}
        objects.append(str(obj))
    proc = subprocess.run([gxx, "-static", "-o", str(out), *objects],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return {"compiler": "mingw", "status": "link failed",
                "stderr": proc.stderr[-800:]}
    return {"compiler": "mingw", "status": "ok", "gcc": gcc, "gxx": gxx}


def find_vcvars() -> str:
    vswhere = Path("C:/Program Files (x86)/Microsoft Visual Studio/Installer/"
                   "vswhere.exe")
    roots = []
    if vswhere.exists():
        proc = subprocess.run([str(vswhere), "-latest", "-products", "*",
                               "-property", "installationPath"],
                              capture_output=True, text=True)
        if proc.returncode == 0:
            roots.append(Path(proc.stdout.strip()))
    for edition in ("Enterprise", "Community", "Professional", "BuildTools"):
        roots.append(Path("C:/Program Files/Microsoft Visual Studio/2022") /
                     edition)
    for root in roots:
        candidate = root / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"
        if candidate.exists():
            return str(candidate)
    return ""


def build_msvc(wlic: Path, out: Path, work: Path) -> dict:
    vcvars = find_vcvars()
    if not vcvars:
        return {"compiler": "msvc", "status": "vcvarsall.bat not found"}
    cpp, c, includes = sources(wlic)
    inc = [f"/I{p}" for p in includes]
    objdir = work / "obj"
    work.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(objdir, ignore_errors=True)
    objdir.mkdir(parents=True, exist_ok=True)

    # 163 translation units in a single cl invocation exceeds the Windows
    # command line limit ("The command line is too long"), so compile in
    # chunks through response files and link the objects afterwards.
    sources_list = [str(p) for p in cpp] + [str(p) for p in c]
    chunk_size = 25
    commands = []
    for index in range(0, len(sources_list), chunk_size):
        chunk = sources_list[index:index + chunk_size]
        response = work / f"compile{index // chunk_size}.rsp"
        response.write_text(" ".join(["/nologo", "/c", "/O2", "/EHsc", "/MT",
                                      f"/Fo{objdir}\\", *inc, *chunk]))
        commands.append(f'cl @"{response}"')
    objects = sorted(str(p) for p in objdir.glob("*.obj"))
    if len(objects) != len(sources_list):
        return {"compiler": "msvc", "status": "object count mismatch",
                "expected": len(sources_list), "got": len(objects)}
    link_response = work / "link.rsp"
    link_response.write_text(" ".join(["/nologo", f'/OUT:"{out}"', *objects]))
    commands.append(f'link @"{link_response}"')
    command = f'call "{vcvars}" x64 >nul && ' + " && ".join(commands)
    proc = subprocess.run(["cmd", "/c", command], capture_output=True,
                          text=True, cwd=str(work))
    if proc.returncode != 0 or not out.exists():
        return {"compiler": "msvc", "status": "build failed",
                "stderr": (proc.stdout + proc.stderr)[-1500:]}
    return {"compiler": "msvc", "status": "ok", "vcvars": vcvars,
            "objects": len(objects)}


def main() -> int:
    wlic = wlic_dir()
    RESULTS.mkdir(exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    exe = RESULTS / ("wl-lic.exe" if sys.platform == "win32" else "wl-lic")
    print(f"whatlicense: {wlic}", flush=True)

    attempts = []
    for builder in (build_mingw, build_msvc):
        if sys.platform != "win32":
            attempts.append({"compiler": builder.__name__,
                             "status": "skipped (not Windows)"})
            continue
        result = builder(wlic, exe, RESULTS / f"wl_lic_obj_{builder.__name__}")
        attempts.append(result)
        print(f"{builder.__name__}: {result['status']}", flush=True)
        if result["status"] == "ok":
            break

    info = {"whatlicense": str(wlic), "attempts": attempts,
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
                handle.write(f"- {attempt['compiler']}: "
                             f"{attempt['status']}\n")
            handle.write("\n")
    return 0 if info["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
