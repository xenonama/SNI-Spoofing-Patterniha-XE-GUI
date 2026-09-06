"""SNI Spoofing GUI v4 (Tkinter, Fluent-dark + animations).

Run:  python gui.py   (Windows 10, preferably as Administrator)
Stdlib only — works on Python 3.8+ (Windows 7 builds) through 3.14.
"""
from __future__ import annotations

import ctypes
import glob
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

if getattr(sys, "frozen", False):
    # PyInstaller onefile: __file__ points into the temp bundle dir,
    # but user data (config/lists/logs) lives next to the .exe.
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
XRAY_CONFIG_PATH = os.path.join(APP_DIR, "xray_config.json")
MAIN_PATH = os.path.join(APP_DIR, "main.py")
BACKEND_EXE = os.path.join(APP_DIR, "sni-backend.exe")
PROFILES_DIR = os.path.join(APP_DIR, "profiles")
LOGS_DIR = os.path.join(APP_DIR, "logs")
IP_LIST_PATH = os.path.join(APP_DIR, "ip_list.txt")
SNI_LIST_PATH = os.path.join(APP_DIR, "sni_list.txt")
# Keep the WinDivert filter + failover list small. File lists can hold
# dozens of candidates; only the fastest few are written into config.
MAX_FILE_ENDPOINTS = 8

# Bypass methods shown in the GUI: (key, title, one-line description).
METHODS = (
    ("auto", "Auto  ★ recommended", "Rotates all methods per connection — best first choice"),
    ("wrong_seq", "Wrong sequence", "One fake packet with an old seq — most compatible"),
    ("wrong_seq_ttl", "Wrong seq + TTL", "Low-TTL trick — stronger against some DPI boxes"),
    ("split_seq", "Split sequence", "Fake handshake sent in 2 pieces — strict filters"),
)

# Modes shown in the GUI: (key, title, description).
MODES = (
    ("SNI Only", "Direct relay", "Apps connect straight to the listen port."),
    ("Trojan + Xray", "Via Xray", "Needs xray.exe — adds SOCKS5 + HTTP proxy ports."),
)

from utils import config_manager as cm
from utils import smart
from utils import lists as lists_mod

# --------------------------------------------------------------------------
# Theme (Fluent-inspired dark)
# --------------------------------------------------------------------------
THEME = {
    "bg": "#0A0C10",        # window (deeper black)
    "sidebar": "#0D0F14",   # nav rail
    "card": "#181C24",       # cards
    "card_edge": "#2A2F3A",  # card border
    "input": "#1E232E",      # entries
    "input_edge": "#4FC3F7",  # entry focus ring
    "header": "#11141A",
    "accent": "#4FC3F7",
    "accent_dim": "#2A6FA0",
    "primary": "#2B88D8",
    "primary_hover": "#3D9CE8",
    "primary_press": "#1E6CB0",
    "success": "#3DDC84",
    "success_dim": "#1E7A4C",
    "danger": "#E5534B",
    "danger_hover": "#F26D66",
    "danger_press": "#B93A34",
    "warning": "#F5B544",
    "fg": "#FFFFFF",
    "muted": "#A0AAB8",
    "faint": "#5C6575",
    "disabled_bg": "#2A2F38",
    "disabled_fg": "#6B7280",
}

# Modern font stack with graceful fallback (Win10/Win11, Python 3.8+).
# Tk falls back silently for missing families, so prefer newer names first.
# NOTE: Tk weight must be "bold"/"normal" — "semibold" raises TclError.
FONT_TITLE = ("Segoe UI Variable", 16, "bold")
FONT_SUB = ("Segoe UI Variable", 10)
FONT_H = ("Segoe UI Semibold", 10)
FONT_N = ("Segoe UI Variable", 10)
FONT_BTN = ("Segoe UI Semibold", 10)
FONT_MONO = ("Cascadia Code", 10)
FONT_MONO_FALLBACK = ("JetBrains Mono", 10)
FONT_STATUS = ("Segoe UI", 10, "bold")


# --------------------------------------------------------------------------
# Small helpers (unchanged behavior)
# --------------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(script: str) -> None:
    if getattr(sys, "frozen", False):
        # Frozen exe already carries a requireAdministrator manifest;
        # just restart the exe itself (no script arg exists in a bundle).
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, None, APP_DIR, 1)
    else:
        params = '"%s"' % script
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, APP_DIR, 1)
    sys.exit(0)


def check_pydivert():
    try:
        import pydivert  # noqa: F401
    except Exception as exc:
        return "pydivert import failed: %s" % exc
    return None


def backend_cmd(*args: str) -> list:
    """Command to launch the injector backend.

    Source runs: [python, main.py, ...]. Frozen exe runs: the sibling
    sni-backend.exe (a frozen GUI must not re-exec itself as backend).
    """
    if getattr(sys, "frozen", False):
        return [BACKEND_EXE] + list(args)
    return [sys.executable, MAIN_PATH] + list(args)


def _is_noise_line(line: str) -> bool:
    """True for harmless-but-spammy injector output that should not hit the console."""
    low = line.lower()
    if "cancelling an overlapped future failed" in low:
        return True
    if "_overlappedfuture" in low and ("winerror 6" in low or "handle is invalid" in low):
        return True
    if "asyncio/windows_events.py" in low and "cancel" in low:
        return True
    if low.strip() in ("future: <_overlappedfuture pending cb=[task.task_wakeup()]>",):
        return True
    return False


def _is_overlapped_tail(line: str) -> bool:
    """Companion lines of the overlapped-cancel spam burst (traceback body)."""
    low = line.lower().strip()
    if low.startswith("future: <_overlappedfuture"):
        return True
    if low == "traceback (most recent call last):":
        return True
    if low.startswith('file "') and "windows_events.py" in low:
        return True
    if low == "self._ov.cancel()":
        return True
    s = low.replace(" ", "")
    if s and set(s) <= set("~^"):
        return True
    if low.startswith("oserror: [winerror 6]"):
        return True
    return False


def _is_routine_injector_line(line: str) -> bool:
    """True for routine per-packet injector chatter that is always hidden.

    These lines are correct but extremely repetitive (one per failed bypass):
    'unexpected ... packet ...', 'reinject ...', 'fake_send failed', etc.
    Stats counters (OK/Fail) + traffic already summarize them, so the console
    never shows them (Verbose toggle removed). Startup lines, FATAL errors and
    smart-tool output are NOT routine and always pass through.
    """
    low = line.lower()
    if "unexpected " in low and "packet" in low:
        return True
    for pat in ("reinject ", "fake_send failed",
                "packet with unknown direction",
                "forward unknown-direction",
                "inject error (surviving)"):
        if pat in low:
            return True
    return False


def save_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def build_xray_config(listen_port: int, socks_port: int, http_port: int,
                       password: str, transport: str, ws_path: str, ws_host: str) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"port": socks_port, "protocol": "socks",
             "settings": {"udp": True, "auth": "noauth"},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
            {"port": http_port, "protocol": "http",
             "settings": {"accounts": [], "allowTransparent": False},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
        ],
        "outbounds": [
            {"protocol": "trojan",
             "settings": {"servers": [
                 {"address": "127.0.0.1", "port": listen_port, "password": password}]},
             "streamSettings": {
                 "network": transport,
                 "wsSettings": {"path": ws_path, "headers": {"Host": ws_host}}}},
            {"protocol": "freedom", "tag": "direct", "settings": {}},
        ],
        "routing": {"rules": [
            {"type": "field", "outboundTag": "direct", "domain": ["geosite:cn"]}]},
    }


def parse_host_list(text: str, default_port: int) -> list:
    """Parse 'ip, ip:port, ...' separated by comma/space/newline."""
    out: list = []
    tokens = text.replace(",", " ").replace(";", " ").split()
    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue
        if ":" in tok:
            ip, _, port_s = tok.partition(":")
            try:
                port = int(port_s)
            except ValueError:
                continue
        else:
            ip, port = tok, default_port
        out.append({"ip": ip.strip(), "port": port})
    return out


def parse_sni_list(text: str) -> list:
    parts = text.replace(",", " ").replace(";", " ").split()
    seen, out = set(), []
    for p in parts:
        p = p.strip()
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def list_profiles() -> list:
    try:
        os.makedirs(PROFILES_DIR, exist_ok=True)
        names = []
        for path in glob.glob(os.path.join(PROFILES_DIR, "*.json")):
            base = os.path.basename(path)
            if base.endswith(".full.json"):
                continue
            names.append(os.path.splitext(base)[0])
        return sorted(names)
    except Exception:
        return []


def valid_profile_name(name: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,40}$", name.strip()))


def fmt_bytes(n) -> str:
    """Human size: 0 B, 1.5 KB, 23.4 MB, 2.0 GB."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "0 B"
    if n < 0:
        n = 0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%d %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024
    return "%.1f TB" % n


# --------------------------------------------------------------------------
# Animated widgets
# --------------------------------------------------------------------------
def _round_rect(canvas: tk.Canvas, x1, y1, x2, y2, r, **kw):
    """Draw a rounded rectangle; returns item id."""
    r = min(r, (x2 - x1) / 2, (y2 - y1) / 2)
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
           x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
           x1, y2, x1, y2 - r, x1, y1 + r, x1, y1, x1 + r, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


class ModernButton(tk.Canvas):
    """Rounded button with hover/press tween + disabled state.

    Compatible subset: .config(state=...), .pack/.grid/.place as usual.
    """

    STYLES = {
        "primary": (THEME["primary"], THEME["primary_hover"], THEME["primary_press"], "#FFFFFF"),
        "danger": (THEME["danger"], THEME["danger_hover"], THEME["danger_press"], "#FFFFFF"),
        "ghost": (THEME["card"], "#252B36", "#22262E", THEME["fg"]),
        "accent": ("#1F6F9B", "#2A86B8", "#185A7D", "#FFFFFF"),
    }

    def __init__(self, parent, text="", command=None, style="ghost", height=34,
                 font=FONT_BTN, align="center", radius=9):
        super().__init__(parent, height=height, bg=THEME["card"] if style == "ghost" else THEME["bg"],
                         highlightthickness=0, bd=0, cursor="hand2")
        self._text = text
        self._command = command
        self._style = style
        self._font = font
        self._align = align
        self._radius = radius
        self._enabled = True
        self._hover = False
        self._press = False
        self._fill = self.STYLES[style][0]
        self._body = None
        self._label = None
        self.bind("<Configure>", lambda e: self._draw())
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
        self._draw()

    # -- compat ------------------------------------------------------
    def config(self, **kw):
        if "state" in kw:
            st = kw.pop("state")
            self._enabled = (st == tk.NORMAL)
            self.configure(cursor="hand2" if self._enabled else "arrow")
            self._draw()
        if "text" in kw:
            self._text = kw.pop("text")
            self._draw()
        if "command" in kw:
            self._command = kw.pop("command")
        if kw:
            super().config(**kw)

    def cget(self, key):
        if key == "state":
            return tk.NORMAL if self._enabled else tk.DISABLED
        return super().cget(key)

    # -- rendering ---------------------------------------------------
    def _colors(self):
        base, hov, press, fg = self.STYLES[self._style]
        if not self._enabled:
            return THEME["disabled_bg"], THEME["disabled_fg"]
        if self._press:
            return press, fg
        if self._hover:
            return hov, fg
        return base, fg

    def _draw(self):
        w = max(2, self.winfo_width())
        h = max(2, self.winfo_height())
        fill, fg = self._colors()
        self.delete("all")
        bg = self.cget("bg")
        self._body = _round_rect(self, 1, 1, w - 1, h - 1, self._radius,
                                 fill=fill, outline="")
        # subtle top highlight for depth
        self.create_line(8, 2, w - 8, 2, fill="#FFFFFF", stipple="gray25")
        anchor = "w" if self._align == "left" else "center"
        x = 14 if self._align == "left" else w / 2
        self._label = self.create_text(x, h / 2, text=self._text, font=self._font,
                                       fill=fg, anchor=anchor)
        self.configure(bg=bg)

    def _on_enter(self, e):
        if not self._enabled:
            return
        self._hover = True
        self._draw()

    def _on_leave(self, e):
        self._hover = False
        self._press = False
        self._draw()

    def _on_press(self, e):
        if not self._enabled:
            return
        self._press = True
        self._draw()

    def _on_release(self, e):
        was = self._press
        self._press = False
        self._draw()
        if was and self._enabled and self._command:
            # click animation: quick dip then fire
            self.after(40, lambda: self._command() if self._enabled else None)


class ToggleSwitch(tk.Canvas):
    """iOS-style toggle bound to a BooleanVar."""

    def __init__(self, parent, variable, width=44, height=24):
        super().__init__(parent, width=width, height=height,
                         bg=THEME["card"], highlightthickness=0, bd=0, cursor="hand2")
        self.var = variable
        self._tw, self._th = width, height
        self.bind("<Button-1>", lambda e: self.toggle())
        self._draw()
        try:
            self.var.trace_add("write", lambda *a: self._draw())
        except Exception:
            pass

    def toggle(self):
        try:
            self.var.set(not self.var.get())
        except Exception:
            pass
        self._draw()

    def _draw(self):
        self.delete("all")
        on = bool(self.var.get())
        w, h, r = self._tw, self._th, self._th / 2
        track = THEME["primary"] if on else "#3A4150"
        _round_rect(self, 1, 1, w - 1, h - 1, r, fill=track, outline="")
        knob_x = w - r - 2 if on else r + 2
        self.create_oval(knob_x - (r - 3), 3, knob_x + (r - 3), h - 3,
                         fill="#FFFFFF", outline="")


SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")


class Toast:
    """Fading bottom-right notification."""

    _active: list = []

    def __init__(self, root: tk.Tk, text: str, kind: str = "info"):
        self.root = root
        color = {"info": THEME["accent"], "success": THEME["success"],
                 "warning": THEME["warning"], "error": THEME["danger"]}.get(kind, THEME["accent"])
        self.win = tk.Toplevel(root)
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        try:
            self.win.attributes("-alpha", 0.0)
        except Exception:
            pass
        frame = tk.Frame(self.win, bg="#10131A", highlightbackground=color,
                         highlightthickness=1)
        frame.pack(fill=tk.BOTH, expand=True)
        tk.Label(frame, text=text, font=FONT_N, fg=THEME["fg"], bg="#10131A",
                 wraplength=300, justify=tk.LEFT).pack(padx=14, pady=10)
        Toast._active.append(self.win)
        if len(Toast._active) > 3:
            try:
                Toast._active[0].destroy()
            except Exception:
                pass
            Toast._active = Toast._active[-3:]
        self._place()
        self._fade_in()

    def _place(self):
        try:
            self.root.update_idletasks()
            rx, ry = self.root.winfo_x(), self.root.winfo_y()
            rw, rh = self.root.winfo_width(), self.root.winfo_height()
            self.win.update_idletasks()
            ww, wh = self.win.winfo_width(), self.win.winfo_height()
            stack = Toast._active.index(self.win)
            self.win.geometry("+%d+%d" % (rx + rw - ww - 24, ry + rh - wh - 24 - stack * (wh + 10)))
        except Exception:
            pass

    def _fade_in(self, a=0.0):
        try:
            a = min(0.96, a + 0.16)
            self.win.attributes("-alpha", a)
            if a < 0.96:
                self.win.after(15, lambda: self._fade_in(a))
            else:
                self.win.after(1500, lambda: self._fade_out(0.96))
        except Exception:
            pass

    def _fade_out(self, a):
        try:
            a = max(0.0, a - 0.16)
            self.win.attributes("-alpha", a)
            if a <= 0.0:
                self.win.destroy()
                if self.win in Toast._active:
                    Toast._active.remove(self.win)
            else:
                self.win.after(25, lambda: self._fade_out(a))
        except Exception:
            pass


# --------------------------------------------------------------------------
# Main GUI
# --------------------------------------------------------------------------
class SpooferGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SNI Spoofer")
        self.root.geometry("1060x760")
        self.root.minsize(940, 660)
        self.root.configure(bg=THEME["bg"])
        try:
            self.root.attributes("-alpha", 0.0)
        except Exception:
            pass

        self._style = ttk.Style()
        try:
            self._style.theme_use("clam")
        except Exception:
            pass
        self._style.configure("Modern.TCombobox", fieldbackground=THEME["input"],
                              background=THEME["input"], foreground=THEME["fg"],
                              arrowcolor=THEME["accent"], borderwidth=0)
        self._style.configure("Modern.Horizontal.TProgressbar", background=THEME["accent"],
                              troughcolor=THEME["header"], borderwidth=0, thickness=4)
        self._style.configure("Modern.Vertical.TScrollbar", background=THEME["input"],
                              troughcolor=THEME["bg"], borderwidth=0, arrowcolor=THEME["muted"])

        self.injector_proc = None
        self.xray_proc = None
        self.running = False
        self.manual_stop = False
        self.start_time = None
        self.msg_q = queue.Queue()
        self.active_conns = 0
        self.total_conns = 0
        self.success_conns = 0
        self.failed_conns = 0
        self.success_rate = 0.0
        self.best_endpoint = ""
        self.best_method = ""
        self.method_rate = 0.0
        self.method_runs = 0
        self.up_bytes = 0
        self.down_bytes = 0
        self.up_rate = 0.0
        self.down_rate = 0.0
        self._prev_up = 0
        self._prev_down = 0
        self._prev_traffic_t = 0.0
        self.restart_tries = 0
        self._cards: list = []
        self._method_rows = {}
        self._mode_rows = {}
        self.log_file = None
        self.busy_jobs = 0
        self._spin_i = 0
        self._pulse_on = False
        self._page = ""
        self._pages = {}
        self._page_canvases = {}
        self._page_bodies = {}
        self._nav_buttons = {}
        self._toast_ok = True

        cfg = cm.load(CONFIG_PATH)

        self.v_listen_host = tk.StringVar(value=str(cfg.get("LISTEN_HOST", "0.0.0.0")))
        self.v_listen_port = tk.StringVar(value=str(cfg.get("LISTEN_PORT", 40443)))
        self.v_fake_sni = tk.StringVar(value=str((cfg.get("FAKE_SNIS") or [""])[0] if cfg.get("FAKE_SNIS") else cfg.get("FAKE_SNI", "")))
        self.v_endpoint_ip = tk.StringVar(value=str(cfg.get("CONNECT_IP", "")))
        self.v_endpoint_port = tk.StringVar(value=str(cfg.get("CONNECT_PORT", 443)))
        self.v_mode = tk.StringVar(value=str(cfg.get("MODE", "SNI Only")))
        self.v_socks = tk.StringVar(value=str(cfg.get("SOCKS5_PORT", 10808)))
        self.v_http = tk.StringVar(value=str(cfg.get("HTTP_PORT", 10809)))
        self.v_password = tk.StringVar(value=str(cfg.get("TROJAN_PASSWORD", "humanity")))
        self.v_transport = tk.StringVar(value=str(cfg.get("TRANSPORT", "ws")))
        self.v_path = tk.StringVar(value=str(cfg.get("WS_PATH", "/assignment")))
        self.v_host = tk.StringVar(value=str(cfg.get("WS_HOST", "www.creationlong.org")))
        self.v_method = tk.StringVar(value=str(cfg.get("BYPASS_METHOD", "auto")))
        self.v_timeout = tk.StringVar(value=str(cfg.get("HANDSHAKE_TIMEOUT", 2.0)))
        self.v_maxconn = tk.StringVar(value=str(cfg.get("MAX_CONNECTIONS", 200)))
        self.v_autorestart = tk.BooleanVar(value=True)
        # Verbose toggle removed: console always behaves as Verbose=OFF.
        try:
            self.v_method.trace_add("write", lambda *a: self._refresh_method_ui())
        except Exception:
            pass
        try:
            self.v_mode.trace_add("write", lambda *a: self._refresh_mode_ui())
        except Exception:
            pass
        try:
            self.file_endpoints: list = lists_mod.load_ip_list(
                IP_LIST_PATH, default_port=int(str(cfg.get("CONNECT_PORT", 443)) or 443))
        except Exception:
            self.file_endpoints = []
        try:
            self.file_snis: list = lists_mod.load_sni_list(SNI_LIST_PATH)
        except Exception:
            self.file_snis = []
        cfg_eps = cfg.get("ENDPOINTS") or []
        cfg_snis = cfg.get("FAKE_SNIS") or []
        if len(cfg_eps) > 1:
            self.extra_eps_text = "; ".join("%s:%s" % (e["ip"], e["port"]) for e in cfg_eps[1:3])
        elif self.file_endpoints:
            self.extra_eps_text = "; ".join(
                "%s:%s" % (e["ip"], e["port"]) for e in self.file_endpoints[:2])
        else:
            self.extra_eps_text = ""
        if len(cfg_snis) > 1:
            self.snis_text = ", ".join(cfg_snis[1:4])
        elif self.file_snis:
            primary = str((cfg_snis or [""])[0] if cfg_snis else cfg.get("FAKE_SNI", ""))
            rest = [s for s in self.file_snis if s != primary][:3]
            self.snis_text = ", ".join(rest)
        else:
            self.snis_text = ""

        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.after(120, self._poll_queue)
        self.root.after(600, self._pulse_loop)
        self.root.after(300, self._spin_loop)
        self.root.after(800, lambda: self._slide_indicator(self._page))

        self._open_log_file()
        self.log("SNI Spoofer ready. Configure, then press START.", "info")
        if self.file_endpoints:
            self.log("Loaded %d endpoint candidate(s) from ip_list.txt "
                     "(sampled, max %d used)." % (len(self.file_endpoints), MAX_FILE_ENDPOINTS), "info")
        elif os.path.exists(IP_LIST_PATH):
            self.log("ip_list.txt found but no usable IPs/CIDRs parsed.", "warning")
        if self.file_snis:
            self.log("Loaded %d SNI candidate(s) from sni_list.txt." % len(self.file_snis), "info")
        elif os.path.exists(SNI_LIST_PATH):
            self.log("sni_list.txt found but no usable SNIs parsed.", "warning")
        if not is_admin():
            self.log("Not Administrator — injector (WinDivert) will fail until restart as admin.", "warning")
        else:
            self.log("Running as Administrator.", "success")
        err = check_pydivert()
        if err:
            self.log("%s — run: pip install -r requirements.txt" % err, "warning")
        if getattr(sys, "frozen", False):
            if not os.path.exists(BACKEND_EXE):
                self.log("sni-backend.exe not found at %s" % BACKEND_EXE, "error")
        elif not os.path.exists(MAIN_PATH):
            self.log("main.py not found at %s" % MAIN_PATH, "error")
        self._fade_window_in()

    # -- animations ------------------------------------------------
    def _fade_window_in(self, a=0.0):
        try:
            a = min(1.0, a + 0.08)
            self.root.attributes("-alpha", a)
            if a < 1.0:
                self.root.after(22, lambda: self._fade_window_in(a))
        except Exception:
            pass

    def _pulse_loop(self):
        try:
            if self.running:
                self._pulse_on = not self._pulse_on
                dot = "#3DDC84" if self._pulse_on else THEME["success_dim"]
                self.status_dot.config(fg=dot)
                self.status_pill.config(highlightbackground=dot)
            else:
                self.status_dot.config(fg="#5C6575")
                self.status_pill.config(highlightbackground=THEME["card_edge"])
        except Exception:
            pass
        self.root.after(550, self._pulse_loop)

    def _spin_loop(self):
        try:
            if self.busy_jobs > 0:
                self._spin_i = (self._spin_i + 1) % len(SPINNER_FRAMES)
                self.lbl_busy.config(text="%s working…" % SPINNER_FRAMES[self._spin_i])
            else:
                self.lbl_busy.config(text="")
        except Exception:
            pass
        self.root.after(110, self._spin_loop)

    def toast(self, text, kind="info"):
        try:
            Toast(self.root, text, kind)
        except Exception:
            pass

    # -- layout ----------------------------------------------------
    def _build(self):
        self._build_header()
        body = tk.Frame(self.root, bg=THEME["bg"])
        body.pack(fill=tk.BOTH, expand=True)
        self._build_sidebar(body)
        right = tk.Frame(body, bg=THEME["bg"])
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 16), pady=(14, 14))
        self.page_host = tk.Frame(right, bg=THEME["bg"])
        self.page_host.pack(fill=tk.BOTH, expand=True)
        self._build_pages()
        self._build_stats(right)
        self._build_console(right)
        self._show_page("bypass", animate=False)

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=THEME["header"], height=66)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        # accent line
        tk.Frame(self.root, bg=THEME["accent"], height=2).pack(fill=tk.X)
        left = tk.Frame(hdr, bg=THEME["header"])
        left.pack(side=tk.LEFT, padx=18, pady=10)
        tk.Label(left, text="SNI Spoofer", font=FONT_TITLE, fg=THEME["fg"],
                 bg=THEME["header"]).pack(side=tk.LEFT)
        tk.Label(left, text="DPI bypass · failover · scoreboard", font=FONT_SUB,
                 fg=THEME["muted"], bg=THEME["header"]).pack(side=tk.LEFT, padx=(12, 0), pady=(6, 0))
        right = tk.Frame(hdr, bg=THEME["header"])
        right.pack(side=tk.RIGHT, padx=18, pady=10)
        self.lbl_uptime = tk.Label(right, text="--:--", font=FONT_N, fg=THEME["muted"],
                                   bg=THEME["header"])
        self.lbl_uptime.pack(side=tk.RIGHT, padx=(12, 0))
        # status pill with pulsing indicator
        self.status_pill = tk.Frame(right, bg=THEME["header"], highlightbackground=THEME["card_edge"],
                                    highlightthickness=1, padx=12, pady=5)
        self.status_pill.pack(side=tk.RIGHT)
        self.status_dot = tk.Label(self.status_pill, text="●", font=("Segoe UI", 12, "bold"),
                                   fg="#5C6575", bg=THEME["header"])
        self.status_dot.pack(side=tk.LEFT)
        self.status_lbl = tk.Label(self.status_pill, text="INACTIVE", font=FONT_STATUS,
                                   fg=THEME["muted"], bg=THEME["header"])
        self.status_lbl.pack(side=tk.LEFT, padx=(6, 0))
        # slim progress bar (visible while starting)
        self.start_bar = ttk.Progressbar(self.root, style="Modern.Horizontal.TProgressbar",
                                         mode="indeterminate", length=200)
        self._bar_running = False

    def _build_sidebar(self, body):
        side = tk.Frame(body, bg=THEME["sidebar"], width=208)
        side.pack(side=tk.LEFT, fill=tk.Y, padx=(16, 12), pady=14)
        side.pack_propagate(False)
        tk.Label(side, text="NAVIGATE", font=("Segoe UI Semibold", 8), fg=THEME["faint"],
                 bg=THEME["sidebar"]).pack(anchor="w", padx=16, pady=(14, 6))
        # Sliding indicator lives in sidebar coords (same parent as the
        # buttons, so winfo_y() lines up). Placed after layout settles.
        self.nav_ind = tk.Frame(side, bg=THEME["accent"], width=4, height=42)
        self.nav_ind.place(x=0, y=40)
        for key, label in (("bypass", "🛡️   DPI Bypass"),
                           ("proxy", "🌐   Proxy / Xray"),
                           ("tools", "🛠   Smart Tools")):
            b = ModernButton(side, text=label, command=lambda k=key: self._show_page(k),
                             style="ghost", height=42, align="left")
            b.configure(bg=THEME["sidebar"])
            b.pack(fill=tk.X, padx=10, pady=3)
            self._nav_buttons[key] = b
        tk.Frame(side, bg="#2A2F3A", height=1).pack(fill=tk.X, padx=16, pady=12)
        tk.Label(side, text="ENGINE", font=("Segoe UI Semibold", 8), fg=THEME["faint"],
                 bg=THEME["sidebar"]).pack(anchor="w", padx=16, pady=(0, 6))
        self.btn_start = ModernButton(side, text="▶   START", command=self.start,
                                       style="primary", height=44)
        self.btn_start.configure(bg=THEME["sidebar"])
        self.btn_start.pack(fill=tk.X, padx=10, pady=3)
        self.btn_stop = ModernButton(side, text="⏹   STOP", command=self.stop,
                                     style="danger", height=40)
        self.btn_stop.configure(bg=THEME["sidebar"])
        self.btn_stop.pack(fill=tk.X, padx=10, pady=3)
        self.btn_stop.config(state=tk.DISABLED)
        for txt, cmd in (("⧉  Copy proxy", self.copy_proxy),
                         ("⬆  Run as admin", lambda: relaunch_as_admin(os.path.abspath(__file__))),
                         ("💾  Save config", self.save_only)):
            b = ModernButton(side, text=txt, command=cmd, style="ghost", height=32)
            b.configure(bg=THEME["sidebar"])
            b.pack(fill=tk.X, padx=10, pady=2)

    def _page_frame(self, name):
        """A scrollable page: outer frame (placed) + canvas + content body."""
        outer = tk.Frame(self.page_host, bg=THEME["bg"])
        canvas = tk.Canvas(outer, bg=THEME["bg"], highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview,
                            style="Modern.Vertical.TScrollbar")
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        body = tk.Frame(canvas, bg=THEME["bg"])
        win = canvas.create_window((0, 0), window=body, anchor="nw")

        def _sync(e=None):
            try:
                canvas.configure(scrollregion=canvas.bbox("all"))
                canvas.itemconfig(win, width=max(1, canvas.winfo_width()))
            except Exception:
                pass

        body.bind("<Configure>", _sync)
        canvas.bind("<Configure>", _sync)
        self._pages[name] = outer
        self._page_canvases[name] = canvas
        self._page_bodies[name] = body
        return body

    def _wheel_scroll(self, event, canvas):
        try:
            canvas.yview_scroll(int(-event.delta / 120), "units")
        except Exception:
            pass
        return "break"

    def _bind_wheel_tree(self, widget, canvas):
        # Scroll the page, but leave text editing and dropdowns alone.
        if isinstance(widget, (tk.Entry, ttk.Combobox, scrolledtext.ScrolledText,
                               tk.Text, tk.Listbox, ttk.Scrollbar)):
            return
        try:
            widget.bind("<MouseWheel>", lambda e: self._wheel_scroll(e, canvas), add="+")
        except Exception:
            pass
        try:
            children = widget.winfo_children()
        except Exception:
            children = []
        for ch in children:
            self._bind_wheel_tree(ch, canvas)

    def _show_page(self, name, animate=True):
        if name == self._page:
            return
        for k, pg in self._pages.items():
            pg.place_forget()
        self._page = name
        pg = self._pages[name]
        try:
            self._page_canvases[name].yview_moveto(0)
        except Exception:
            pass
        # refresh nav highlight
        for k, b in self._nav_buttons.items():
            b._style = "accent" if k == name else "ghost"
            b._draw()
        self._slide_indicator(name)
        if animate:
            self._slide_page_in(pg)
        else:
            pg.place(relx=0, rely=0, relwidth=1, relheight=1)

    def _slide_indicator(self, name, step=0):
        try:
            target = self._nav_buttons[name].winfo_y()
        except Exception:
            return
        try:
            cur = self.nav_ind.winfo_y()
        except Exception:
            cur = target
        if abs(target - cur) < 2 or step > 12:
            self.nav_ind.place(x=0, y=target)
            return
        nxt = cur + (target - cur) * 0.45
        self.nav_ind.place(x=0, y=nxt)
        self.root.after(12, lambda: self._slide_indicator(name, step + 1))

    def _slide_page_in(self, pg, step=0):
        total = 4
        if step >= total:
            pg.place(relx=0, rely=0, relwidth=1, relheight=1)
            return
        t = step / total
        pg.place(relx=0.05 * (1 - t), rely=0, relwidth=0.95 + 0.05 * t, relheight=1)
        self.root.after(12, lambda: self._slide_page_in(pg, step + 1))

    # -- pages -----------------------------------------------------
    def _build_pages(self):
        p1 = self._page_frame("bypass")
        self._card(p1, "Connection").pack(fill=tk.X, pady=(0, 14))
        card = self._cards[-1]
        self._row(card, "Listen host", self.v_listen_host)
        self._row(card, "Listen port", self.v_listen_port, w=12)
        self._row(card, "Endpoint IP (primary)", self.v_endpoint_ip)
        self._row(card, "Endpoint port", self.v_endpoint_port, w=12)
        tk.Frame(p1, bg="#2A2F3A", height=1).pack(fill=tk.X, pady=(0, 14))
        self._card(p1, "Spoof").pack(fill=tk.X, pady=(0, 14))
        card = self._cards[-1]
        self._row(card, "Fake SNI (primary)", self.v_fake_sni)
        tk.Label(card, text="Bypass method — tap a card", bg=THEME["card"],
                 fg=THEME["muted"], font=FONT_N).pack(anchor="w", padx=14, pady=(6, 2))
        self._method_wrap = tk.Frame(card, bg=THEME["card"])
        self._method_wrap.pack(fill=tk.X, padx=14, pady=2)
        for key, title, desc in METHODS:
            self._method_rows[key] = self._selector_row(
                self._method_wrap, title, desc, lambda k=key: self.v_method.set(k))
        self.lbl_method_hint = tk.Label(card, text="", bg=THEME["card"],
                                        fg=THEME["success"], font=("Segoe UI", 8))
        self.lbl_method_hint.pack(anchor="w", padx=14, pady=(0, 4))
        trow = tk.Frame(card, bg=THEME["card"])
        trow.pack(fill=tk.X, padx=14, pady=4)
        tk.Label(trow, text="Timeout", bg=THEME["card"], fg=THEME["muted"],
                 font=FONT_N).pack(side=tk.LEFT)
        self._entry(trow, self.v_timeout, width=6).pack(side=tk.LEFT, padx=(6, 2))
        tk.Label(trow, text="Max conn", bg=THEME["card"], fg=THEME["muted"],
                 font=FONT_N).pack(side=tk.LEFT, padx=(10, 2))
        self._entry(trow, self.v_maxconn, width=7).pack(side=tk.LEFT, padx=2)
        arow = tk.Frame(card, bg=THEME["card"])
        arow.pack(fill=tk.X, padx=14, pady=(2, 8))
        tk.Label(arow, text="Auto-restart on crash", bg=THEME["card"], fg=THEME["muted"],
                 font=FONT_N).pack(side=tk.LEFT)
        ToggleSwitch(arow, self.v_autorestart).pack(side=tk.LEFT, padx=10)
        self._card(p1, "Failover  ·  extra endpoints + SNIs").pack(fill=tk.X, pady=(0, 14))
        card = self._cards[-1]
        self._row(card, "Extra endpoints", None, w=40, text_var_name="extra",
                  hint="ip[:port], comma separated")
        self._row(card, "Extra SNIs", None, w=40, text_var_name="snis",
                  hint="comma separated, rotated")
        self._card(p1, "Profiles").pack(fill=tk.X)
        card = self._cards[-1]
        prow = tk.Frame(card, bg=THEME["card"])
        prow.pack(fill=tk.X, padx=14, pady=8)
        self.v_profile = tk.StringVar(value="")
        self.cbo_profile = ttk.Combobox(prow, textvariable=self.v_profile, width=24,
                                        values=list_profiles(), style="Modern.TCombobox")
        self.cbo_profile.pack(side=tk.LEFT, padx=(0, 6))
        for txt, cmd in (("Load", self.profile_load), ("Save", self.profile_save),
                         ("Delete", self.profile_delete), ("↻", self.profile_refresh)):
            ModernButton(prow, text=txt, command=cmd, style="ghost", height=30).pack(side=tk.LEFT, padx=3)

        p2 = self._page_frame("proxy")
        self._card(p2, "Mode — tap a card").pack(fill=tk.X, pady=(0, 14))
        card = self._cards[-1]
        self._mode_wrap = tk.Frame(card, bg=THEME["card"])
        self._mode_wrap.pack(fill=tk.X, padx=14, pady=4)
        for key, title, desc in MODES:
            self._mode_rows[key] = self._selector_row(
                self._mode_wrap, title, desc, lambda k=key: self.v_mode.set(k))
        self.lbl_mode_hint = tk.Label(card, text="", bg=THEME["card"],
                                      fg=THEME["muted"], font=("Segoe UI", 8),
                                      wraplength=640, justify=tk.LEFT)
        self.lbl_mode_hint.pack(anchor="w", padx=14, pady=(0, 8))
        self._card(p2, "Proxy output").pack(fill=tk.X, pady=(0, 14))
        card = self._cards[-1]
        self._row(card, "SOCKS5 port", self.v_socks, w=12)
        self._row(card, "HTTP port", self.v_http, w=12)
        self._card(p2, "Trojan / transport").pack(fill=tk.X)
        card = self._cards[-1]
        self._row(card, "Trojan password", self.v_password)
        self._row(card, "Transport", self.v_transport, w=12)
        self._row(card, "WS path", self.v_path)
        self._row(card, "WS host", self.v_host)

        p3 = self._page_frame("tools")
        self._card(p3, "Smart tools   ·   no Admin needed except START").pack(fill=tk.BOTH, expand=True)
        card = self._cards[-1]
        thead = tk.Frame(card, bg=THEME["card"])
        thead.pack(fill=tk.X, padx=14, pady=(8, 2))
        tk.Label(thead, text="Probes use plain TCP/TLS — DPI success still depends on network.",
                 bg=THEME["card"], fg=THEME["faint"], font=("Segoe UI", 8)).pack(side=tk.LEFT)
        self.lbl_busy = tk.Label(thead, text="", bg=THEME["card"], fg=THEME["accent"], font=FONT_N)
        self.lbl_busy.pack(side=tk.RIGHT)
        for txt, cmd in [
            ("📶  Ping SNIs on primary endpoint", self.smart_rank_snis),
            ("🏆  Ping SNIs + use best SNI to spoof", self.smart_use_best_sni),
            ("🔄  Reload ip_list.txt / sni_list.txt", self.smart_reload_lists),
        ]:
            ModernButton(card, text=txt, command=cmd, style="ghost",
                         height=33, align="left").pack(fill=tk.X, padx=14, pady=2)
        self._refresh_method_ui()
        self._refresh_mode_ui()
        for pname, pbody in self._page_bodies.items():
            self._bind_wheel_tree(pbody, self._page_canvases[pname])

    def _card(self, parent, title):
        outer = tk.Frame(parent, bg=THEME["card_edge"])
        inner = tk.Frame(outer, bg=THEME["card"])
        inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        tk.Label(inner, text=title.upper(), font=("Segoe UI Semibold", 8),
                 fg=THEME["accent"], bg=THEME["card"]).pack(anchor="w", padx=14, pady=(10, 2))
        self._cards.append(inner)
        return outer

    def _entry(self, parent, var, width=30):
        e = tk.Entry(parent, textvariable=var, bg=THEME["input"], fg=THEME["fg"],
                     font=FONT_N, relief=tk.FLAT, width=width, insertbackground=THEME["accent"],
                     highlightthickness=1, highlightbackground=THEME["card"],
                     highlightcolor=THEME["input_edge"], selectbackground=THEME["accent_dim"])
        return e

    def _row(self, parent, label, var, w=30, text_var_name=None, hint=None):
        r = tk.Frame(parent, bg=THEME["card"])
        r.pack(fill=tk.X, padx=14, pady=4)
        tk.Label(r, text=label, width=20, anchor="w", bg=THEME["card"],
                 fg=THEME["muted"], font=FONT_N).pack(side=tk.LEFT)
        if text_var_name == "extra":
            self.e_extra = self._entry(r, None, width=w)
            self.e_extra.insert(0, self.extra_eps_text)
            self.e_extra.pack(side=tk.LEFT, padx=8, ipady=4, fill=tk.X, expand=True)
        elif text_var_name == "snis":
            self.e_snis = self._entry(r, None, width=w)
            self.e_snis.insert(0, self.snis_text)
            self.e_snis.pack(side=tk.LEFT, padx=8, ipady=4, fill=tk.X, expand=True)
        elif var is not None:
            self._entry(r, var, width=w).pack(side=tk.LEFT, padx=8, ipady=4)
        if hint:
            tk.Label(r, text=hint, bg=THEME["card"], fg=THEME["faint"],
                     font=("Segoe UI", 8)).pack(side=tk.LEFT)

    # -- selector cards (methods + modes) --------------------------
    def _selector_row(self, parent, title, desc, on_pick):
        outer = tk.Frame(parent, bg=THEME["card_edge"], cursor="hand2")
        outer.pack(fill=tk.X, pady=3)
        inner = tk.Frame(outer, bg=THEME["input"], cursor="hand2")
        inner.pack(fill=tk.X, padx=1, pady=1)
        dot = tk.Label(inner, text="○", font=("Segoe UI", 12), fg=THEME["faint"],
                       bg=THEME["input"], cursor="hand2", width=3)
        dot.pack(side=tk.LEFT, padx=(4, 0))
        txt = tk.Frame(inner, bg=THEME["input"], cursor="hand2")
        txt.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), pady=6)
        t1 = tk.Label(txt, text=title, font=FONT_BTN, fg=THEME["fg"],
                      bg=THEME["input"], anchor="w", cursor="hand2")
        t1.pack(anchor="w")
        t2 = tk.Label(txt, text=desc, font=("Segoe UI", 8), fg=THEME["muted"],
                      bg=THEME["input"], anchor="w", wraplength=560, justify=tk.LEFT,
                      cursor="hand2")
        t2.pack(anchor="w")
        row = {"outer": outer, "inner": inner, "dot": dot, "txt": txt,
               "t1": t1, "t2": t2}
        for w in (outer, inner, dot, txt, t1, t2):
            w.bind("<Button-1>", lambda e: on_pick())
        return row

    def _paint_selector_row(self, row, selected):
        # Selected: accent border + subtle tint across the whole card.
        row["outer"].configure(bg=THEME["accent"] if selected else THEME["card_edge"])
        inner_bg = "#1E2A36" if selected else THEME["input"]
        try:
            row["inner"].configure(bg=inner_bg)
            row["txt"].configure(bg=inner_bg)
            row["t1"].configure(bg=inner_bg)
            row["t2"].configure(bg=inner_bg)
            row["dot"].configure(bg=inner_bg)
        except Exception:
            pass
        row["dot"].configure(text="◉" if selected else "○",
                             fg=THEME["accent"] if selected else THEME["faint"])

    def _refresh_method_ui(self):
        rows = getattr(self, "_method_rows", None)
        if not rows:
            return
        try:
            cur = self.v_method.get().strip()
        except Exception:
            return
        if cur not in rows:
            try:
                self.v_method.set("auto")
            except Exception:
                pass
            return
        for k, row in rows.items():
            self._paint_selector_row(row, k == cur)

    def _xray_status(self):
        if os.path.exists(os.path.join(APP_DIR, "xray.exe")):
            return "xray.exe found"
        return "xray.exe MISSING — SNI injector still works alone"

    def _refresh_mode_ui(self):
        rows = getattr(self, "_mode_rows", None)
        if not rows:
            return
        try:
            cur = self.v_mode.get().strip()
        except Exception:
            return
        if cur not in rows:
            try:
                self.v_mode.set("SNI Only")
            except Exception:
                pass
            return
        for k, row in rows.items():
            self._paint_selector_row(row, k == cur)
        try:
            if cur == "Trojan + Xray":
                self.lbl_mode_hint.configure(
                    text="Xray listens SOCKS5 :%s + HTTP :%s and forwards into the injector. %s."
                         % (self.v_socks.get().strip(), self.v_http.get().strip(), self._xray_status()),
                    fg=THEME["muted"])
            else:
                self.lbl_mode_hint.configure(
                    text="Apps connect straight to the injector at the listen host/port above. No extra files needed.",
                    fg=THEME["muted"])
        except Exception:
            pass

    # -- stats + console -------------------------------------------
    def _build_stats(self, right):
        bar = tk.Frame(right, bg="#141922", highlightbackground=THEME["card_edge"],
                       highlightthickness=1, pady=6)
        bar.pack(fill=tk.X, pady=(10, 0))
        stats_font = ("Segoe UI Variable", 9)
        self.lbl_active = tk.Label(bar, text="● Active 0", font=stats_font, fg=THEME["accent"], bg="#141922")
        self.lbl_active.pack(side=tk.LEFT, padx=10)
        self.lbl_total = tk.Label(bar, text="Total 0", font=stats_font, fg=THEME["fg"], bg="#141922")
        self.lbl_total.pack(side=tk.LEFT, padx=10)
        self.lbl_okfail = tk.Label(bar, text="OK 0 · Fail 0", font=stats_font, fg=THEME["muted"], bg="#141922")
        self.lbl_okfail.pack(side=tk.LEFT, padx=10)
        self.lbl_best = tk.Label(bar, text="Best —", font=stats_font, fg=THEME["muted"], bg="#141922")
        self.lbl_best.pack(side=tk.LEFT, padx=10)
        self.lbl_method = tk.Label(bar, text="Method —", font=stats_font, fg=THEME["muted"], bg="#141922")
        self.lbl_method.pack(side=tk.LEFT, padx=10)
        self.lbl_up = tk.Label(bar, text="▲ 0 B", font=stats_font, fg=THEME["success"], bg="#141922")
        self.lbl_up.pack(side=tk.LEFT, padx=10)
        self.lbl_down = tk.Label(bar, text="▼ 0 B", font=stats_font, fg=THEME["accent"], bg="#141922")
        self.lbl_down.pack(side=tk.LEFT, padx=10)

    def _build_console(self, right):
        outer = tk.Frame(right, bg=THEME["card_edge"])
        outer.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.console_outer = outer
        self._console_expanded = True
        box = tk.Frame(outer, bg=THEME["card"])
        box.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        h = tk.Frame(box, bg=THEME["card"])
        h.pack(fill=tk.X, padx=12, pady=(8, 2))
        tk.Label(h, text="LIVE CONSOLE", font=("Segoe UI Semibold", 8),
                 fg=THEME["accent"], bg=THEME["card"]).pack(side=tk.LEFT)
        self.btn_console_toggle = tk.Button(
            h, text="\u25bc", font=("Segoe UI", 8), fg=THEME["accent"],
            bg=THEME["card"], activebackground=THEME["card"],
            activeforeground=THEME["accent"], relief=tk.FLAT, bd=0,
            width=3, cursor="hand2", command=self._toggle_console)
        self.btn_console_toggle.pack(side=tk.LEFT, padx=(6, 0))
        ModernButton(h, text="Export", command=self.export_log, style="ghost", height=26).pack(side=tk.RIGHT, padx=(6, 0))
        ModernButton(h, text="Clear", command=self.clear_log, style="ghost", height=26).pack(side=tk.RIGHT, padx=(0, 6))
        # Verbose toggle removed: console always hides routine packet notes.
        try:
            import tkinter.font as tkfont
            available = set(tkfont.families())
            if "Cascadia Code" in available:
                mono_font = ("Cascadia Code", 10)
            elif "JetBrains Mono" in available:
                mono_font = ("JetBrains Mono", 10)
            else:
                mono_font = ("Consolas", 10)
        except Exception:
            mono_font = FONT_MONO
        self.console = scrolledtext.ScrolledText(box, bg="#10131A", fg=THEME["fg"],
                                                 font=mono_font, relief=tk.FLAT, wrap=tk.WORD, height=8,
                                                 insertbackground=THEME["accent"],
                                                 selectbackground=THEME["accent_dim"])
        self.console.pack(fill=tk.BOTH, expand=True, padx=12, pady=(2, 12))
        for tag, col in (("info", THEME["accent"]), ("success", THEME["success"]),
                         ("warning", THEME["warning"]), ("error", THEME["danger"])):
            self.console.tag_config(tag, foreground=col)

    def _toggle_console(self):
        """Collapse/expand only the console text widget; header stays visible."""
        if getattr(self, "_console_expanded", True):
            self.console.pack_forget()
            self.console_outer.pack_configure(expand=False, fill=tk.X)
            self.btn_console_toggle.configure(text="\u25b6")
            self._console_expanded = False
        else:
            self.console.pack(fill=tk.BOTH, expand=True, padx=12, pady=(2, 12))
            self.console_outer.pack_configure(expand=True, fill=tk.BOTH)
            self.btn_console_toggle.configure(text="\u25bc")
            self._console_expanded = True

    # -- config ----------------------------------------------------
    def _collect(self):
        try:
            default_port = int(self.v_endpoint_port.get().strip() or 443)
        except ValueError:
            return None, "Endpoint port must be a number"
        endpoints = [{"ip": self.v_endpoint_ip.get().strip(), "port": default_port}]
        endpoints += parse_host_list(self.e_extra.get(), default_port)
        endpoints = [e for e in endpoints if e["ip"]]
        snis = [self.v_fake_sni.get().strip()] + parse_sni_list(self.e_snis.get())
        snis = [s for s in snis if s]
        try:
            cfg = {
                "LISTEN_HOST": self.v_listen_host.get().strip() or "0.0.0.0",
                "LISTEN_PORT": int(self.v_listen_port.get().strip()),
                "CONNECT_IP": endpoints[0]["ip"] if endpoints else "",
                "CONNECT_PORT": endpoints[0]["port"] if endpoints else 443,
                "ENDPOINTS": endpoints,
                "FAKE_SNI": snis[0] if snis else "",
                "FAKE_SNIS": snis,
                "BYPASS_METHOD": self.v_method.get().strip(),
                "HANDSHAKE_TIMEOUT": float(self.v_timeout.get().strip()),
                "MAX_CONNECTIONS": int(self.v_maxconn.get().strip()),
                "FAKE_DELAY": 0.001,
                "SOCKS5_PORT": int(self.v_socks.get().strip()),
                "HTTP_PORT": int(self.v_http.get().strip()),
                "MODE": self.v_mode.get(),
                "TROJAN_PASSWORD": self.v_password.get(),
                "TRANSPORT": self.v_transport.get().strip() or "ws",
                "WS_PATH": self.v_path.get().strip() or "/",
                "WS_HOST": self.v_host.get().strip(),
            }
        except (ValueError, IndexError):
            return None, "Numeric fields (ports/timeout/max-conn) are invalid"
        cfg = cm.migrate(cfg)
        errs = cm.validate(cfg)
        if errs:
            return None, "; ".join(errs[:3])
        return cfg, None

    def save_only(self, silent=False):
        cfg, err = self._collect()
        if err:
            messagebox.showerror("Invalid config", err)
            return
        cm.save(CONFIG_PATH, cfg)
        xray_cfg = build_xray_config(int(cfg["LISTEN_PORT"]), int(cfg["SOCKS5_PORT"]), int(cfg["HTTP_PORT"]),
                                     cfg["TROJAN_PASSWORD"], cfg["TRANSPORT"], cfg["WS_PATH"], cfg["WS_HOST"])
        save_json(XRAY_CONFIG_PATH, xray_cfg)
        self.log("Saved config.json (+.full.json) + xray_config.json", "success")
        if not silent:
            self.toast("Configuration saved", "success")

    # -- profiles --------------------------------------------------
    def _current_cfg_or_warn(self):
        cfg, err = self._collect()
        if err:
            messagebox.showerror("Invalid config", err)
            return None
        return cfg

    def apply_cfg(self, cfg: dict):
        cfg = cm.migrate(cfg)
        self.v_listen_host.set(str(cfg.get("LISTEN_HOST", "0.0.0.0")))
        self.v_listen_port.set(str(cfg.get("LISTEN_PORT", 40443)))
        snis = cfg.get("FAKE_SNIS") or [cfg.get("FAKE_SNI", "")]
        self.v_fake_sni.set(str(snis[0] if snis else ""))
        self.e_snis.delete(0, tk.END)
        self.e_snis.insert(0, ", ".join(snis[1:4]))
        eps = cfg.get("ENDPOINTS") or []
        self.v_endpoint_ip.set(str(eps[0]["ip"]) if eps else "")
        self.v_endpoint_port.set(str(eps[0]["port"]) if eps else "443")
        self.e_extra.delete(0, tk.END)
        self.e_extra.insert(0, "; ".join("%s:%s" % (e["ip"], e["port"]) for e in eps[1:3]))
        self.v_method.set(str(cfg.get("BYPASS_METHOD", "wrong_seq")))
        self.v_timeout.set(str(cfg.get("HANDSHAKE_TIMEOUT", 2.0)))
        self.v_maxconn.set(str(cfg.get("MAX_CONNECTIONS", 200)))
        self.v_mode.set(str(cfg.get("MODE", "SNI Only")))
        self.v_socks.set(str(cfg.get("SOCKS5_PORT", 10808)))
        self.v_http.set(str(cfg.get("HTTP_PORT", 10809)))
        self.v_password.set(str(cfg.get("TROJAN_PASSWORD", "humanity")))
        self.v_transport.set(str(cfg.get("TRANSPORT", "ws")))
        self.v_path.set(str(cfg.get("WS_PATH", "/assignment")))
        self.v_host.set(str(cfg.get("WS_HOST", "www.creationlong.org")))

    def profile_refresh(self):
        try:
            self.cbo_profile.config(values=list_profiles())
        except Exception:
            pass

    def profile_save(self):
        cfg = self._current_cfg_or_warn()
        if cfg is None:
            return
        name = (self.v_profile.get() or "").strip()
        if not name:
            messagebox.showinfo("Profile", "Type a profile name first (letters, digits, _ - .).")
            return
        if not valid_profile_name(name):
            messagebox.showerror("Profile", "Invalid name. Use letters/digits/_/-/. (max 41 chars).")
            return
        try:
            os.makedirs(PROFILES_DIR, exist_ok=True)
            with open(os.path.join(PROFILES_DIR, name + ".json"), "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            self.profile_refresh()
            self.log("Profile saved: %s" % name, "success")
            self.toast("Profile '%s' saved" % name, "success")
        except Exception as exc:
            messagebox.showerror("Profile", "Save failed: %s" % exc)

    def profile_load(self):
        name = (self.v_profile.get() or "").strip()
        if not name:
            messagebox.showinfo("Profile", "Select or type a profile name first.")
            return
        path = os.path.join(PROFILES_DIR, name + ".json")
        if not os.path.exists(path):
            messagebox.showerror("Profile", "Not found: %s" % name)
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            self.apply_cfg(cfg)
            self.log("Profile loaded: %s (press SAVE to apply to config.json)" % name, "success")
            self.toast("Profile '%s' loaded" % name, "success")
        except Exception as exc:
            messagebox.showerror("Profile", "Load failed: %s" % exc)

    def profile_delete(self):
        name = (self.v_profile.get() or "").strip()
        if not name:
            return
        path = os.path.join(PROFILES_DIR, name + ".json")
        try:
            if os.path.exists(path):
                if messagebox.askyesno("Profile", "Delete profile '%s'?" % name):
                    os.remove(path)
                    self.profile_refresh()
                    self.log("Profile deleted: %s" % name, "warning")
        except Exception as exc:
            messagebox.showerror("Profile", "Delete failed: %s" % exc)

    # -- smart tools -----------------------------------------------
    def _all_endpoints(self) -> list:
        cfg, _ = self._collect()
        if cfg:
            return cfg["ENDPOINTS"]
        return [{"ip": self.v_endpoint_ip.get().strip(), "port": 443}]

    def _sni_candidates(self, limit: int = 60) -> list:
        if self.file_snis:
            return list(self.file_snis[:limit])
        out = [self.v_fake_sni.get().strip()] + parse_sni_list(self.e_snis.get())
        return [s for s in out if s][:limit]

    def _primary_endpoint(self):
        ip = self.v_endpoint_ip.get().strip()
        try:
            port = int(self.v_endpoint_port.get().strip() or 443)
        except ValueError:
            port = 443
        return ip, port

    def _run_bg(self, fn, *args):
        self.busy_jobs += 1
        def wrapper():
            try:
                fn(*args)
            finally:
                self.msg_q.put(("busy", -1))
        threading.Thread(target=wrapper, args=(), daemon=True).start()

    def smart_rank_snis(self):
        ip, port = self._primary_endpoint()
        snis = self._sni_candidates()
        if not ip:
            self.log("Set a primary Endpoint IP first.", "warning")
            return
        if not snis:
            self.log("No SNIs to ping — fill sni_list.txt or the SNI fields.", "warning")
            return
        self.log("Pinging %d SNI(s) on %s:%s (TLS handshake)..." % (len(snis), ip, port), "info")

        def job():
            ranked = smart.rank_snis(ip, port, snis)
            for r in ranked[:20]:
                status = "%sms %s" % (r["latency_ms"], r["tls_version"]) if r["ok"] else "FAIL (%s)" % r["error"][:60]
                self.msg_q.put(("log", "smart", "%s -> %s" % (r["sni"], status)))
            ok = [r for r in ranked if r["ok"]]
            self.msg_q.put(("log", "smart",
                            "Best SNI: %s (%sms, %d/%d OK)" % (ok[0]["sni"], ok[0]["latency_ms"], len(ok), len(ranked))
                            if ok else "No SNI answered on %s:%s! Try another endpoint." % (ip, port)))
        self._run_bg(job)

    def smart_use_best_sni(self):
        ip, port = self._primary_endpoint()
        snis = self._sni_candidates()
        if not ip:
            self.log("Set a primary Endpoint IP first.", "warning")
            return
        if not snis:
            self.log("No SNIs to ping — fill sni_list.txt or the SNI fields.", "warning")
            return
        self.log("Pinging %d SNI(s) on %s:%s, will use the fastest..." % (len(snis), ip, port), "info")

        def job():
            ranked = smart.rank_snis(ip, port, snis)
            ok = [r for r in ranked if r["ok"]]
            if not ok:
                self.msg_q.put(("log", "smart", "No SNI answered on %s:%s." % (ip, port)))
                return
            best = ok[0]
            self.msg_q.put(("use_best_sni", best))
            self.msg_q.put(("log", "smart",
                            "Best SNI to spoof: %s (%sms). Press SAVE/START." % (best["sni"], best["latency_ms"])))
        self._run_bg(job)

    def smart_reload_lists(self):
        try:
            port = int(self.v_endpoint_port.get().strip() or 443)
        except ValueError:
            port = 443
        try:
            self.file_endpoints = lists_mod.load_ip_list(IP_LIST_PATH, default_port=port)
        except Exception:
            self.file_endpoints = []
        try:
            self.file_snis = lists_mod.load_sni_list(SNI_LIST_PATH)
        except Exception:
            self.file_snis = []
        self.log("Reloaded: %d endpoint(s) from ip_list.txt, "
                 "%d SNI(s) from sni_list.txt." % (len(self.file_endpoints), len(self.file_snis)), "success")
        try:
            if self.file_endpoints and not self.e_extra.get().strip():
                self.e_extra.delete(0, tk.END)
                self.e_extra.insert(0, "; ".join(
                    "%s:%s" % (e["ip"], e["port"]) for e in self.file_endpoints[:4]))
            if self.file_snis and not self.e_snis.get().strip():
                primary = self.v_fake_sni.get().strip()
                rest = [s for s in self.file_snis if s != primary][:4]
                self.e_snis.delete(0, tk.END)
                self.e_snis.insert(0, ", ".join(rest))
        except Exception:
            pass
        self.toast("Lists reloaded", "success")

    # -- process control -------------------------------------------
    def _bar_show(self, show):
        try:
            if show and not self._bar_running:
                self.start_bar.place(relx=0, rely=0, relwidth=1, height=4)
                self.start_bar.start(14)
                self._bar_running = True
                self.root.after(8000, lambda: self._bar_show(False))
            elif not show and self._bar_running:
                self.start_bar.stop()
                self.start_bar.place_forget()
                self._bar_running = False
        except Exception:
            pass

    def start(self):
        if self.running:
            self.log("Already running.", "warning")
            return
        cfg, err = self._collect()
        if err:
            messagebox.showerror("Invalid config", err)
            self.log("Invalid config: %s" % err, "error")
            return
        if getattr(sys, "frozen", False):
            if not os.path.exists(BACKEND_EXE):
                messagebox.showerror("Missing file", "sni-backend.exe not found:\n%s" % BACKEND_EXE)
                return
        elif not os.path.exists(MAIN_PATH):
            messagebox.showerror("Missing file", "main.py not found:\n%s" % MAIN_PATH)
            return
        try:
            lp = int(cfg["LISTEN_PORT"])
            if not smart.is_port_free("127.0.0.1", lp):
                if not messagebox.askyesno("Port busy",
                        "Port %d seems IN USE. Start anyway?" % lp):
                    return
        except Exception:
            pass
        if not is_admin():
            if not messagebox.askyesno("Not admin",
                    "You are NOT Administrator. WinDivert will likely fail.\nStart anyway?"):
                return
        self.save_only(silent=True)
        cfg, err = self._collect()
        if err:
            return
        eps = ", ".join("%s:%s" % (e["ip"], e["port"]) for e in cfg["ENDPOINTS"][:4])
        self.log("Starting: %s:%s -> [%s] "
                 "(SNI=%s, method=%s)" % (cfg["LISTEN_HOST"], cfg["LISTEN_PORT"], eps,
                                          cfg["FAKE_SNIS"][0], cfg["BYPASS_METHOD"]), "info")
        try:
            self.manual_stop = False
            self.restart_tries = 0
            self.injector_proc = self._spawn(backend_cmd("--config", CONFIG_PATH))
        except Exception as exc:
            self.log("Failed to start injector: %s" % exc, "error")
            return
        if cfg["MODE"] == "Trojan + Xray":
            xray_exe = os.path.join(APP_DIR, "xray.exe")
            if not os.path.exists(xray_exe):
                self.log("xray.exe not found — running SNI injector only.", "warning")
            else:
                try:
                    self.xray_proc = self._spawn([xray_exe, "-c", XRAY_CONFIG_PATH])
                    self.log("Xray started (SOCKS5 :%s, HTTP :%s)"
                             % (cfg["SOCKS5_PORT"], cfg["HTTP_PORT"]), "success")
                except Exception as exc:
                    self.log("Xray start failed: %s" % exc, "warning")
        self.running = True
        self.start_time = time.time()
        self.active_conns = self.total_conns = self.success_conns = self.failed_conns = 0
        self.success_rate = 0.0
        self.best_endpoint = ""
        self.best_method = ""
        self.method_rate = 0.0
        self.method_runs = 0
        # Traffic tracker reset for this run.
        self.up_bytes = 0
        self.down_bytes = 0
        self.up_rate = 0.0
        self.down_rate = 0.0
        self._prev_up = 0
        self._prev_down = 0
        self._prev_traffic_t = time.time()
        self._refresh_stats()
        self._update_method_hint()
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self._set_status(True)
        self._bar_show(True)
        threading.Thread(target=self._reader, args=(self.injector_proc, "injector"), daemon=True).start()
        if self.xray_proc:
            threading.Thread(target=self._reader, args=(self.xray_proc, "xray"), daemon=True).start()
        self.log("Injector started.", "success")
        self.toast("Engine started", "success")

    def _spawn(self, cmd: list):
        if sys.platform == "win32":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            return subprocess.Popen(cmd, cwd=APP_DIR, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1,
                                    startupinfo=si, creationflags=subprocess.CREATE_NO_WINDOW)
        return subprocess.Popen(cmd, cwd=APP_DIR, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)

    def _reader(self, proc, tag: str):
        try:
            assert proc.stdout is not None
            noise_tail = 0  # lines remaining in an overlapped-cancel spam burst
            for line in iter(proc.stdout.readline, ""):
                if not line:
                    break
                line = line.rstrip("\r\n")
                if not line:
                    continue
                if line.lstrip().startswith('{"type"'):
                    try:
                        obj = json.loads(line)
                        if obj.get("type") == "stats":
                            self.msg_q.put(("stats", obj))
                            continue
                    except Exception:
                        pass
                if _is_noise_line(line):
                    noise_tail = 8
                    continue
                if noise_tail > 0 and _is_overlapped_tail(line):
                    noise_tail -= 1
                    continue
                noise_tail = 0
                self.msg_q.put(("log", tag, line))
        except Exception as exc:
            self.msg_q.put(("log", tag, "[%s] reader error: %s" % (tag, exc)))
        finally:
            self.msg_q.put(("exit", tag))

    def _poll_queue(self):
        try:
            while True:
                msg = self.msg_q.get_nowait()
                kind = msg[0]
                if kind == "stats":
                    _, obj = msg
                    try:
                        self.active_conns = int(obj.get("active", 0))
                        self.total_conns = int(obj.get("total", 0))
                        self.success_conns = int(obj.get("success", 0))
                        self.failed_conns = int(obj.get("failed", 0))
                        self.success_rate = float(obj.get("success_rate", 0.0))
                        be = str(obj.get("best_endpoint", "") or "")
                        if be:
                            self.best_endpoint = be
                        else:
                            sb = obj.get("scoreboard") or {}
                            eps = sb.get("endpoints") or []
                            if eps:
                                self.best_endpoint = str(eps[0].get("key", ""))
                        bm = str(obj.get("best_method", "") or "")
                        if bm:
                            self.best_method = bm
                            meths = obj.get("methods") or []
                            if meths:
                                self.method_rate = float(meths[0].get("rate", 0.0))
                                self.method_runs = int(meths[0].get("ok", 0)) + int(meths[0].get("fail", 0))
                        # --- traffic tracker: totals from backend, rates local ---
                        try:
                            new_up = int(obj.get("up_bytes", self.up_bytes) or 0)
                            new_down = int(obj.get("down_bytes", self.down_bytes) or 0)
                        except (TypeError, ValueError):
                            new_up, new_down = self.up_bytes, self.down_bytes
                        now = time.time()
                        if self._prev_traffic_t:
                            dt = now - self._prev_traffic_t
                            if dt >= 0.5:
                                # Guard against backend restart (counters reset).
                                if new_up >= self._prev_up and new_down >= self._prev_down and dt > 0:
                                    self.up_rate = (new_up - self._prev_up) / dt
                                    self.down_rate = (new_down - self._prev_down) / dt
                                self._prev_up, self._prev_down = new_up, new_down
                                self._prev_traffic_t = now
                        else:
                            self._prev_up, self._prev_down = new_up, new_down
                            self._prev_traffic_t = now
                        self.up_bytes, self.down_bytes = new_up, new_down
                    except Exception:
                        pass
                    self._refresh_stats()
                    self._update_method_hint()
                elif kind == "busy":
                    try:
                        self.busy_jobs = max(0, self.busy_jobs + int(msg[1]))
                    except Exception:
                        pass
                elif kind == "use_best_sni":
                    _, best = msg
                    sni = str(best.get("sni", "") or "").strip()
                    if sni:
                        self.v_fake_sni.set(sni)
                    self._append("Fake SNI set to %s "
                                 "(%sms on primary endpoint)" % (sni, best.get("latency_ms")), "success")
                    self.toast("Best SNI applied: %s" % sni, "success")
                elif kind == "log":
                    _, tag, line = msg
                    low = line.lower()
                    if "server started on" in low and tag == "injector":
                        self._bar_show(False)
                    # Console always hides routine injector packet chatter
                    # (total silence). Smart-tool, gui and error lines pass.
                    if tag == "injector" and _is_routine_injector_line(line):
                        # Still surface WinDivert failures that hide in routine flow.
                        if tag == "injector" and ("windivert" in low or "access is denied" in low):
                            self._append("[gui] WinDivert failed — run GUI as Administrator "
                                         "(RUN AS ADMIN) and press START again.", "error")
                        continue
                    if "error" in low or "fatal" in low or "traceback" in low:
                        lvl = "error"
                    elif "warn" in low:
                        lvl = "warning"
                    elif "success" in low or "started" in low or "ok (" in low or "tls ok" in low:
                        lvl = "success"
                    else:
                        lvl = "info"
                    self._append("[%s] %s" % (tag, line), lvl)
                    if tag == "injector" and ("windivert" in low or "access is denied" in low):
                        self._append("[gui] WinDivert failed — run GUI as Administrator "
                                     "(RUN AS ADMIN) and press START again.", "error")
                elif kind == "exit":
                    _, tag = msg
                    self._append("[%s] process exited." % tag, "warning")
                    if tag == "injector" and self.running and not self.manual_stop:
                        self.root.after(0, self._on_injector_exit)
        except queue.Empty:
            pass
        if self.running and self.start_time:
            secs = int(time.time() - self.start_time)
            self.lbl_uptime.config(text="%02d:%02d" % (secs // 60, secs % 60))
        self.root.after(120, self._poll_queue)

    def _refresh_stats(self):
        self.lbl_active.config(text="● Active %d" % self.active_conns)
        self.lbl_total.config(text="Total %d" % self.total_conns)
        self.lbl_okfail.config(text="OK %d · Fail %d" % (self.success_conns, self.failed_conns))
        best = self.best_endpoint or "—"
        self.lbl_best.config(text="Best %s (%.0f%%)" % (best, self.success_rate * 100.0))
        if self.best_method:
            runs = self.method_runs
            self.lbl_method.config(text="Method %s · %.0f%% (%d)" % (self.best_method, self.method_rate * 100.0, runs))
        else:
            self.lbl_method.config(text="Method —")
        # Traffic tracker: totals + live rates.
        try:
            self.lbl_up.config(text="▲ %s (%s/s)" % (fmt_bytes(self.up_bytes), fmt_bytes(self.up_rate)))
        except Exception:
            pass
        try:
            self.lbl_down.config(text="▼ %s (%s/s)" % (fmt_bytes(self.down_bytes), fmt_bytes(self.down_rate)))
        except Exception:
            pass

    def _update_method_hint(self):
        """Live scoreboard hint under the method cards."""
        try:
            if self.best_method and self.method_runs > 0:
                self.lbl_method_hint.configure(
                    text="Live best: %s · %.0f%% success over %d bypass(es) — Auto already uses it. "
                         "Pick one card to force it." % (self.best_method, self.method_rate * 100.0, self.method_runs))
            else:
                self.lbl_method_hint.configure(text="")
        except Exception:
            pass

    def _on_injector_exit(self):
        if self.manual_stop or not self.running:
            return
        if self.v_autorestart.get() and self.restart_tries < 3:
            self.restart_tries += 1
            self.log("Injector crashed — auto-restart %d/3 in 2s..." % self.restart_tries, "warning")
            self._terminate(self.xray_proc)
            self.xray_proc = None
            self.injector_proc = None
            self.running = False
            self.root.after(2000, self._do_restart)
            return
        self._terminate(self.xray_proc)
        self.xray_proc = None
        self.injector_proc = None
        self.running = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self._set_status(False)
        self._bar_show(False)
        self.log("Injector exited — port in use? not admin? WinDivert? (disable Auto-restart to stop retrying)", "error")

    def _do_restart(self):
        if self.manual_stop or self.running:
            return
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self._set_status(False)
        self.start()
        self.restart_tries = min(self.restart_tries, 3)

    def stop(self):
        if not self.running and self.injector_proc is None:
            return
        self.manual_stop = True
        self.log("Stopping...", "warning")
        self._terminate(self.injector_proc)
        self._terminate(self.xray_proc)
        self.injector_proc = None
        self.xray_proc = None
        self.running = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self._set_status(False)
        self._bar_show(False)
        self.lbl_uptime.config(text="--:--")
        # Session summary: traffic totals.
        try:
            self._append("Session traffic: ▲ %s up · ▼ %s down "
                         "(OK %d · Fail %d)." % (fmt_bytes(self.up_bytes), fmt_bytes(self.down_bytes),
                                                 self.success_conns, self.failed_conns), "info")
        except Exception:
            pass
        self.log("Stopped.", "warning")
        self.toast("Engine stopped", "warning")

    @staticmethod
    def _terminate(proc):
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
        except Exception:
            pass

    # -- misc UI ---------------------------------------------------
    def _set_status(self, on: bool):
        if on:
            self.status_dot.config(fg="#3DDC84")
            self.status_lbl.config(text="ACTIVE", fg="#3DDC84", font=FONT_STATUS)
            try:
                self.status_pill.config(highlightbackground="#3DDC84")
            except Exception:
                pass
        else:
            self.status_dot.config(fg="#5C6575")
            self.status_lbl.config(text="INACTIVE", fg=THEME["muted"], font=FONT_STATUS)
            try:
                self.status_pill.config(highlightbackground=THEME["card_edge"])
            except Exception:
                pass

    def log(self, text: str, level: str = "info"):
        self.msg_q.put(("log", "gui", text))

    def _append(self, text: str, level: str):
        ts = datetime.now().strftime("%H:%M:%S")
        line = "[%s] %s\n" % (ts, text)
        self.console.insert(tk.END, line, level)
        self.console.see(tk.END)
        try:
            if int(self.console.index("end-1c").split(".")[0]) > 3000:
                self.console.delete("1.0", "500.0")
        except Exception:
            pass
        try:
            if self.log_file:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(line)
        except Exception:
            pass

    def _open_log_file(self):
        try:
            os.makedirs(LOGS_DIR, exist_ok=True)
            self.log_file = os.path.join(LOGS_DIR, "gui_%s.log" % datetime.now().strftime("%Y%m%d"))
        except Exception:
            self.log_file = None

    def clear_log(self):
        self.console.delete("1.0", tk.END)

    def export_log(self):
        try:
            name = os.path.join(APP_DIR, "sni_log_%s.txt" % datetime.now().strftime("%Y%m%d_%H%M%S"))
            with open(name, "w", encoding="utf-8") as f:
                f.write(self.console.get("1.0", tk.END))
            self._append("Log exported: %s" % name, "success")
            self.toast("Log exported", "success")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def copy_proxy(self):
        info = "SOCKS5: 127.0.0.1:%s\nHTTP: 127.0.0.1:%s" % (self.v_socks.get().strip(), self.v_http.get().strip())
        self.root.clipboard_clear()
        self.root.clipboard_append(info)
        self._append("Proxy info copied to clipboard.", "success")
        self.toast("Proxy info copied", "success")

    def on_closing(self):
        if self.running:
            if messagebox.askyesno("Exit", "Injector is running. Stop and exit?"):
                self.manual_stop = True
                self.stop()
                self.root.destroy()
        else:
            self.root.destroy()


def main():
    os.chdir(APP_DIR)
    root = tk.Tk()
    SpooferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
