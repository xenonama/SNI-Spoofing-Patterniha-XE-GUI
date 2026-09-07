# exporter.py — export this project (Python) to Windows .exe files.
#
# What it does:
#   1. Checks the environment (Windows, Python, tkinter, pydivert, PyInstaller).
#   2. Builds two exes with PyInstaller in one command:
#        SNI-Spoofer.exe  <- gui.py      (windowed, asks for Admin via manifest)
#        sni-backend.exe  <- main.py     (console, injector backend, also Admin)
#      The GUI starts the backend automatically; both files must stay together.
#   3. Copies runtime data files next to the exes
#      (config.json, ip_list.txt, sni_list.txt, xray_config.json).
#   4. Writes a README + verifies the output (file sizes, backend present).
#   5. Optionally zips the dist folder for sharing.
#
# Usage (just run it — missing deps and the obsolete pathlib
# backport are fixed automatically):
#   python exporter.py                        (default: onefile build to dist/)
#   python exporter.py --mode onedir --zip
#   python exporter.py --check-only           (env check only, changes nothing)
#   python exporter.py --no-auto-fix          (never touch pip packages)
#
# Notes:
#   - Run with the TARGET interpreter (e.g. 32-bit python -> 32-bit exes).
#   - Win7 builds need Python 3.8 + PyInstaller 4.10 + pydivert 2.1.0
#     (see build_exe.py header). This script works with newer setups too.
#   - Output dir already contains SNI-Spoofer.exe + sni-backend.exe + data files:
#     keep them together or START will fail ("sni-backend.exe not found").
from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys

APP_DIR = os.path.dirname(os.path.abspath(__file__))

GUI_SCRIPT = os.path.join(APP_DIR, "gui.py")
BACKEND_SCRIPT = os.path.join(APP_DIR, "main.py")

GUI_NAME = "SNI-Spoofer"
BACKEND_NAME = "sni-backend"

# Runtime files the exes read from disk (next to the .exe, NOT bundled inside).
DATA_FILES = ["config.json", "ip_list.txt", "sni_list.txt", "xray_config.json"]

README_TEXT = """SNI Spoofer ({arch})
================================

Files must stay together in one folder:
  SNI-Spoofer.exe   - the GUI (double-click, accept the Admin prompt)
  sni-backend.exe   - injector backend (started by the GUI, do not delete)
  config.json       - settings (edited by the GUI)
  ip_list.txt       - endpoint candidates (CIDR / IP / IP:port per line)
  sni_list.txt      - fake-SNI candidates (one per line)

Run:
  1. Right-click SNI-Spoofer.exe -> Run as administrator
     (the .exe also requests elevation itself).
  2. Smart Tools -> Reload lists -> Rank / use fastest.
  3. Press START.

Notes:
  - WinDivert driver installs automatically on first START (Admin required).
  - Keep sni-backend.exe next to SNI-Spoofer.exe or START will fail.
  - Optional: put xray.exe next to SNI-Spoofer.exe (or in PATH) to enable
    "Trojan + Xray" mode. Without it the SNI injector still works alone.
  - {arch} build runs on {runs_on}.
"""


def log(msg: str) -> None:
    print(msg, flush=True)


def run(cmd: list) -> None:
    log("+ " + " ".join(cmd))
    subprocess.check_call(cmd, cwd=APP_DIR)


def pathlib_backport_path() -> str | None:
    """Return site-packages path of the obsolete 'pathlib' backport, or None.

    PyInstaller aborts when this PyPI package is installed because it shadows
    the stdlib pathlib. Stdlib origin looks like '.../Lib/pathlib/__init__.py';
    the backport lives under 'site-packages'.
    """
    try:
        import importlib.util
        spec = importlib.util.find_spec("pathlib")
        origin = (getattr(spec, "origin", "") or "")
        if "site-packages" in origin.replace("\\", "/").lower():
            return origin
    except Exception:
        pass
    for cand in (os.path.join(sys.prefix, "Lib", "site-packages", "pathlib.py"),
                 os.path.join(sys.prefix, "Lib", "site-packages", "pathlib", "__init__.py")):
        try:
            if os.path.isfile(cand):
                return cand
        except Exception:
            continue
    return None


def _can_import(name: str) -> bool:
    """True if `import name` works right now (re-checks after pip installs)."""
    try:
        import importlib
        importlib.invalidate_caches()
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


def auto_fix(auto: bool) -> bool:
    """Silently fix safe, known blockers. Returns True if anything changed.

    Only ever touches these exact packages (nothing else on the system):
      - uninstall obsolete 'pathlib' backport (shadows stdlib, blocks PyInstaller)
      - install 'pyinstaller' if missing (the export tool itself)
      - install 'pydivert' if missing (declared in requirements.txt)
    Never raises — failures are logged and reported by check_env() afterwards.
    """
    if not auto:
        return False
    changed = False
    bad = pathlib_backport_path()
    if bad:
        log("Auto-fix: removing obsolete 'pathlib' backport (%s) ..." % bad)
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", "pathlib"],
                                  cwd=APP_DIR)
            changed = True
        except subprocess.CalledProcessError as exc:
            log("Auto-fix failed (pip exit %s) — run manually: \"%s\" -m pip uninstall -y pathlib"
                % (exc.returncode, sys.executable))
        except Exception as exc:
            log("Auto-fix failed: %s" % exc)
    if not _can_import("PyInstaller"):
        log("Auto-fix: installing PyInstaller ...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"],
                                  cwd=APP_DIR)
            changed = True
        except subprocess.CalledProcessError as exc:
            log("Auto-fix failed (pip exit %s) — run manually: pip install pyinstaller"
                % exc.returncode)
        except Exception as exc:
            log("Auto-fix failed: %s" % exc)
    if not _can_import("pydivert"):
        log("Auto-fix: installing pydivert ...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pydivert"],
                                  cwd=APP_DIR)
            changed = True
        except subprocess.CalledProcessError as exc:
            log("Auto-fix failed (pip exit %s) — run manually: pip install -r requirements.txt"
                % exc.returncode)
        except Exception as exc:
            log("Auto-fix failed: %s" % exc)
    return changed


def check_env() -> list:
    """Return a list of problems (empty = OK). Never raises."""
    problems: list = []
    bad = pathlib_backport_path()
    if bad:
        problems.append(
            "obsolete 'pathlib' backport installed (%s) — PyInstaller refuses to run with it. "
            "Fix: \"%s\" -m pip uninstall -y pathlib  (or just re-run exporter: auto-fix is ON by default)"
            % (bad, sys.executable))
    if not os.path.isfile(GUI_SCRIPT):
        problems.append("gui.py not found at %s" % GUI_SCRIPT)
    if not os.path.isfile(BACKEND_SCRIPT):
        problems.append("main.py not found at %s" % BACKEND_SCRIPT)
    try:
        import tkinter  # noqa: F401
    except Exception as exc:
        problems.append("tkinter unavailable (%s) — GUI exe still builds, but test it on Windows." % exc)
    if sys.platform != "win32":
        problems.append("not running on Windows (sys.platform=%s) — the .exe output only runs on Windows." % sys.platform)
    try:
        import pydivert  # noqa: F401
    except Exception as exc:
        problems.append("pydivert not installed (%s) — run: pip install -r requirements.txt" % exc)
    try:
        import PyInstaller  # noqa: F401
        log("PyInstaller: %s" % PyInstaller.__version__)
    except Exception:
        problems.append("PyInstaller not installed — run: pip install pyinstaller")
    for fn in DATA_FILES:
        if not os.path.exists(os.path.join(APP_DIR, fn)):
            problems.append("data file missing: %s" % fn)
    return problems


def build_one(script: str, name: str, dist: str, work: str, windowed: bool,
              uac_admin: bool, onefile: bool) -> None:
    """Build a single exe with PyInstaller. Raises on failure."""
    cmd = [sys.executable, "-m", "PyInstaller",
           "--noconfirm", "--clean",
           "--name", name,
           "--distpath", dist,
           "--workpath", work,
           "--specpath", work]
    cmd.append("--onefile" if onefile else "--onedir")
    # Bundle the WinDivert driver shipped inside the pydivert package.
    cmd += ["--collect-all", "pydivert"]
    # Make sure our local packages are found even if cwd differs.
    cmd += ["--paths", APP_DIR]
    if windowed:
        cmd.append("--windowed")
    else:
        cmd.append("--console")
    if uac_admin:
        cmd.append("--uac-admin")
    cmd.append(script)
    run(cmd)


def copy_data_files(dist: str) -> None:
    for fn in DATA_FILES:
        src = os.path.join(APP_DIR, fn)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(dist, fn))
            log("copied %s" % fn)
        else:
            log("WARNING: data file not found, skipped: %s" % fn)


def write_readme(dist: str, arch: str) -> None:
    text = README_TEXT.format(
        arch=arch,
        runs_on="64-bit Windows" if arch == "64-bit" else "32-bit AND 64-bit Windows")
    with open(os.path.join(dist, "README.txt"), "w", encoding="utf-8") as f:
        f.write(text)


def verify(dist: str) -> bool:
    """Check the dist folder looks runnable. Returns True if OK."""
    ok = True
    ext = ".exe" if sys.platform == "win32" else ""
    # On non-Windows hosts PyInstaller still emits extensionless binaries;
    # accept either name when verifying.
    for base in (GUI_NAME, BACKEND_NAME):
        found = any(os.path.isfile(os.path.join(dist, base + e)) for e in (".exe", ""))
        if not found:
            log("ERROR: missing output: %s(.exe) in %s" % (base, dist))
            ok = False
    _ = ext
    log("dist contents:")
    try:
        for fn in sorted(os.listdir(dist)):
            p = os.path.join(dist, fn)
            size = os.path.getsize(p) // 1024 if os.path.isfile(p) else 0
            log("  %s  (%d KB)" % (fn, size))
    except Exception as exc:
        log("ERROR: cannot list dist: %s" % exc)
        return False
    return ok


def make_zip(dist: str, arch: str) -> str:
    """Zip the dist folder next to it. Returns the zip path."""
    base = os.path.abspath(dist.rstrip(os.sep))
    zip_base = "%s-%s" % (base, "win64" if arch == "64-bit" else "win32")
    # shutil.make_archive appends .zip itself.
    for suffix in ("", "-win64", "-win32"):
        candidate = base + suffix + ".zip"
        if os.path.exists(candidate):
            try:
                os.remove(candidate)
            except Exception:
                pass
    out = shutil.make_archive(zip_base, "zip", root_dir=os.path.dirname(base),
                              base_dir=os.path.basename(base))
    log("zipped: %s" % out)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Export SNI-Spoofer (gui.py + main.py) to Windows .exe files.")
    ap.add_argument("--dist", default="dist",
                    help="output folder (default: dist)")
    ap.add_argument("--mode", choices=["onefile", "onedir"], default="onefile",
                    help="onefile = single .exe each (default); onedir = faster start, folder output")
    ap.add_argument("--no-uac", action="store_true",
                    help="do NOT embed requireAdministrator manifest (default: embed it)")
    ap.add_argument("--zip", action="store_true",
                    help="also create a shareable .zip of the dist folder")
    ap.add_argument("--check-only", action="store_true",
                    help="only check environment, do not build")
    ap.add_argument("--skip-checks", action="store_true",
                    help="build even if environment checks report problems")
    ap.add_argument("--fix-pathlib", action="store_true",
                    help="kept for compatibility: auto-fix is now ON by default, this flag is a no-op")
    ap.add_argument("--no-auto-fix", action="store_true",
                    help="never install/uninstall pip packages; only report problems")
    args = ap.parse_args()

    bits = struct.calcsize("P") * 8
    arch = "64-bit" if bits == 64 else "32-bit"
    log("Exporter: building %s exes with Python %s ..." % (arch, sys.version.split()[0]))

    auto = not args.no_auto_fix
    problems = check_env()
    if problems:
        log("Environment check found %d issue(s):" % len(problems))
        for p in problems:
            log("  ! %s" % p)
    else:
        log("Environment check: OK")

    # Smart default: silently fix safe, known blockers (unless --no-auto-fix
    # or --check-only, which must not change anything), then re-check.
    if not args.check_only and auto:
        if auto_fix(True):
            log("Re-checking environment after auto-fix ...")
            problems = check_env()
            if problems:
                for p in problems:
                    log("  ! %s" % p)
            else:
                log("Environment check: OK")

    if args.check_only:
        return 1 if problems else 0
    if problems and not args.skip_checks:
        # Abort on missing project files, or on dependency problems that are
        # STILL broken after the auto-fix attempt above (e.g. no network for
        # pip). Pure warnings (non-Windows host, tkinter note) never block.
        fatal = any(k in p for p in problems
                    for k in ("gui.py", "main.py", "data file missing",
                              "PyInstaller", "pydivert", "pathlib"))
        if fatal:
            log("Aborted: unfixable problems remain (see above). Fix them manually "
                "or re-run with --skip-checks to try anyway.")
            return 2
        log("Continuing despite %d warning(s) ..." % len(problems))

    # Resolve a relative --dist against the project dir (not cwd), so launching
    # via 'C:\\...\exporter.py' from another folder still outputs next to the project.
    dist = args.dist if os.path.isabs(args.dist) else os.path.join(APP_DIR, args.dist)
    dist = os.path.abspath(dist)
    work = dist + "-work"
    for d in (dist, work):
        os.makedirs(d, exist_ok=True)

    onefile = (args.mode == "onefile")
    uac = not args.no_uac

    try:
        log("[1/2] Building GUI: gui.py -> %s ..." % GUI_NAME)
        build_one(GUI_SCRIPT, GUI_NAME, dist, work, windowed=True, uac_admin=uac, onefile=onefile)
        log("[2/2] Building backend: main.py -> %s ..." % BACKEND_NAME)
        build_one(BACKEND_SCRIPT, BACKEND_NAME, dist, work, windowed=False, uac_admin=uac, onefile=onefile)
    except subprocess.CalledProcessError as exc:
        log("BUILD FAILED (PyInstaller exit %s). See output above." % exc.returncode)
        if pathlib_backport_path():
            log("Likely cause: obsolete 'pathlib' backport is still installed. Fix: "
                "\"%s\" -m pip uninstall -y pathlib, then re-run exporter."
                % sys.executable)
        return 3

    copy_data_files(dist)
    write_readme(dist, arch)

    if not verify(dist):
        log("Build finished with ERRORS — check missing files above.")
        return 4

    if args.zip:
        try:
            make_zip(dist, arch)
        except Exception as exc:
            log("WARNING: zip failed: %s" % exc)

    log("OK: exes ready in %s — keep all files together, run %s as Administrator."
        % (dist, GUI_NAME))
    return 0


def _pause_if_double_clicked() -> None:
    """Keep the console window open when launched via double-click (no args)."""
    try:
        if sys.platform == "win32" and len(sys.argv) == 1:
            input("Done — press ENTER to exit ...")
    except Exception:
        pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    finally:
        _pause_if_double_clicked()
