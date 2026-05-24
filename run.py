# run.py (فایل جدید برای اجرای GUI)
import subprocess
import sys
import os

if __name__ == "__main__":
    if sys.platform == "win32":
        subprocess.Popen(
            [sys.executable, "sni_spoofer_gui.py"],
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    else:
        subprocess.Popen([sys.executable, "sni_spoofer_gui.py"])
