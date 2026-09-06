# run.py - launcher for the new GUI (gui.py).
# Old GUI is preserved as sni_spoofer_gui.old.py
import os
import subprocess
import sys

APP_DIR = os.path.dirname(os.path.abspath(__file__))

if __name__ == "__main__":
    target = os.path.join(APP_DIR, "gui.py")
    if sys.platform == "win32":
        subprocess.Popen(
            [sys.executable, target],
            cwd=APP_DIR,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    else:
        subprocess.Popen([sys.executable, target], cwd=APP_DIR)
