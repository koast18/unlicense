#!/usr/bin/env python3
"""Compiler discovery shared by the spikes.

The GitHub runner is not guaranteed to have the mingw toolchain: fetching it
from the winlibs releases goes through api.github.com, which rate-limits the
shared runner IP (observed: "HTTP Error 403: rate limit exceeded", which then
cascaded into a missing toolchain). Visual Studio, on the other hand, is
always on windows-2022, so the policy here is:

  * MSVC first for everything the spikes build (VS is part of the image)
  * mingw as the fallback / when a decorated-symbol build is required
    (the stub builder needs it; see scripts/stub_missing_dlls.py)

`compile_c` and `compile_cpp` hide which one was used behind a result dict so
the caller can report it.
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IS_WINDOWS = sys.platform == "win32"
ARCH = "x64" if sys.maxsize > 2 ** 32 else "x86"


def mingw(arch: str = None):
    """(gcc, gxx) for `arch`, or (None, None).

    Looks under tools/mingw/<arch>/mingw{32,64}/bin (where
    scripts/install_mingw.py puts it) and then on PATH. Note that
    install_mingw.install() returns no compiler path on its "already
    installed" short-circuit, which is why the disk lookup is authoritative.
    """
    arch = arch or ARCH
    stem = "i686-w64-mingw32" if arch == "x86" else "x86_64-w64-mingw32"
    gcc_name = stem + "-gcc.exe" if IS_WINDOWS else stem + "-gcc"
    gxx_name = stem + "-g++.exe" if IS_WINDOWS else stem + "-g++"
    for candidate in sorted((ROOT / "tools" / "mingw" / arch)
                            .glob("*/bin/" + gcc_name)):
        return str(candidate), str(candidate.parent / gxx_name)
    gcc = shutil.which(gcc_name)
    if gcc:
        return gcc, str(Path(gcc).parent / gxx_name)
    return None, None


def vcvars() -> str:
    """Path to vcvarsall.bat, or ""."""
    vswhere = Path("C:/Program Files (x86)/Microsoft Visual Studio/Installer/"
                   "vswhere.exe")
    roots = []
    if vswhere.exists():
        proc = subprocess.run([str(vswhere), "-latest", "-products", "*",
                               "-property", "installationPath"],
                              capture_output=True, text=True)
        if proc.returncode == 0 and proc.stdout.strip():
            roots.append(Path(proc.stdout.strip()))
    for edition in ("Enterprise", "Community", "Professional", "BuildTools"):
        roots.append(Path("C:/Program Files/Microsoft Visual Studio/2022") /
                     edition)
    for root in roots:
        candidate = root / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"
        if candidate.exists():
            return str(candidate)
    return ""


def msvc_arch() -> str:
    return "x86" if ARCH == "x86" else "x64"


def _run_msvc(command: str, cwd: Path = None):
    # cmd /c needs the entire command wrapped in an extra pair of quotes when
    # it starts with a quoted path, otherwise it treats the quoted vcvarsall
    # path itself as the program to run ("...vcvarsall.bat" is not recognized).
    return subprocess.run(["cmd", "/c", f'"{command}"'], capture_output=True,
                          text=True, cwd=str(cwd) if cwd else None)


def compile_c(source: Path, out: Path, opt: int = 0,
              defines: tuple = ()) -> dict:
    """Build one C file into `out`. Returns {ok, compiler, log}."""
    attempts = []
    vc = vcvars()
    if IS_WINDOWS and vc:
        command = (f'call "{vc}" {msvc_arch()} >nul && cl /nologo /O{opt} '
                   f'/Fe:"{out}" {" ".join(defines)} "{source}"')
        proc = _run_msvc(command, cwd=out.parent)
        log = (proc.stdout or "") + (proc.stderr or "")
        attempts.append({"compiler": "msvc", "rc": proc.returncode,
                         "log": log[-600:]})
        if proc.returncode == 0 and out.exists():
            return {"ok": True, "compiler": "msvc", "attempts": attempts}
    gcc, _ = mingw()
    if gcc:
        flags = ["-static"] if IS_WINDOWS else ["-no-pie"]
        proc = subprocess.run([gcc, f"-O{opt}", *flags, *defines,
                               "-o", str(out), str(source)],
                              capture_output=True, text=True)
        label = "mingw" if IS_WINDOWS else "gcc"
        attempts.append({"compiler": label, "rc": proc.returncode,
                         "log": ((proc.stdout or "") +
                                 (proc.stderr or ""))[-600:]})
        if proc.returncode == 0 and out.exists():
            return {"ok": True, "compiler": label, "attempts": attempts}
    return {"ok": False, "compiler": None, "attempts": attempts,
            "error": "no compiler produced " + str(out)}


def compile_cpp(sources: list, out: Path, includes: list, objdir: Path,
                opt: int = 2) -> dict:
    """Build a mixed C/C++ program (wl-lic). Returns {ok, compiler, ...}."""
    attempts = []
    vc = vcvars()
    if IS_WINDOWS and vc:
        shutil.rmtree(objdir, ignore_errors=True)
        objdir.mkdir(parents=True, exist_ok=True)
        inc = [f"/I{p}" for p in includes]
        objects = []
        failed = None
        for source in sources:
            obj = objdir / (source.stem + ".obj")
            command = (f'call "{vc}" {msvc_arch()} >nul && cl /nologo /c '
                       f'/O{opt} /EHsc /MT /Fo"{obj}" {"/I" + str(includes[0])}'
                       f' {" ".join(inc)} "{source}"')
            proc = _run_msvc(command, cwd=objdir)
            if proc.returncode != 0 or not obj.exists():
                failed = {"file": source.name,
                          "log": ((proc.stdout or "") +
                                  (proc.stderr or ""))[-800:]}
                break
            objects.append(str(obj))
        if failed is None and objects:
            link_rsp = objdir / "link.rsp"
            link_rsp.write_text(" ".join(["/nologo", f'/OUT:"{out}"',
                                          *objects]))
            proc = _run_msvc(f'call "{vc}" {msvc_arch()} >nul && '
                             f'link @"{link_rsp}"', cwd=objdir)
            attempts.append({"compiler": "msvc",
                             "objects": len(objects),
                             "rc": proc.returncode,
                             "log": ((proc.stdout or "") +
                                     (proc.stderr or ""))[-600:]})
            if proc.returncode == 0 and out.exists():
                return {"ok": True, "compiler": "msvc",
                        "objects": len(objects), "attempts": attempts}
        else:
            attempts.append({"compiler": "msvc", "status": "compile failed",
                             "detail": failed})

    gcc, gxx = mingw()
    if gcc and gxx:
        shutil.rmtree(objdir, ignore_errors=True)
        objdir.mkdir(parents=True, exist_ok=True)
        inc = [f"-I{p}" for p in includes]
        # wl-lic was written against MSVC's headers, which pull the C string
        # functions in transitively; gcc needs them spelled out (crypt.cpp
        # uses strlen without including <cstring>).
        forced = ["-include", "cstring", "-include", "cstdio",
                  "-include", "cstdlib", "-include", "cstdint",
                  "-include", "string", "-include", "cmath"]
        objects = []
        failed = None
        for source in sources:
            obj = objdir / (source.stem + ".o")
            if source.suffix == ".c":
                cmd = [gcc, "-c", "-O1", "-w", *inc, "-o", str(obj),
                       str(source)]
            else:
                cmd = [gxx, "-c", "-O1", "-w", "-std=c++17", *forced, *inc,
                       "-o", str(obj), str(source)]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                failed = {"file": source.name,
                          "log": (proc.stderr or "")[-800:]}
                break
            objects.append(str(obj))
        if failed is None and objects:
            proc = subprocess.run([gxx, "-static", "-o", str(out), *objects],
                                  capture_output=True, text=True)
            attempts.append({"compiler": "mingw", "objects": len(objects),
                             "rc": proc.returncode,
                             "log": (proc.stderr or "")[-600:]})
            if proc.returncode == 0 and out.exists():
                return {"ok": True, "compiler": "mingw",
                        "objects": len(objects), "attempts": attempts}
        else:
            attempts.append({"compiler": "mingw", "status": "compile failed",
                             "detail": failed})
    return {"ok": False, "compiler": None, "attempts": attempts,
            "error": "no toolchain built " + str(out)}
