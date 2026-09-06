"""SNI Spoofing GUI v3 (Tkinter-only, smarter + stronger).

Run:  python gui.py   (Windows, preferably as Administrator)
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

from utils import config_manager as cm
from utils import smart
from utils import lists as lists_mod

COLORS = {
    "bg": "#1e1e1e", "card": "#2b2b2b", "input": "#3a3a3a",
    "header": "#252526", "primary": "#0078d4", "success": "#4caf50",
    "danger": "#d32f2f", "warning": "#ff9800", "fg": "#ffffff", "muted": "#aaaaaa",
}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(script: str) -> None:
    params = f'"{script}"'
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, APP_DIR, 1)
    sys.exit(0)


def check_pydivert() -> str | None:
    try:
        import pydivert  # noqa: F401
    except Exception as exc:
        return f"pydivert import failed: {exc}"
    return None


def backend_cmd(*args: str) -> list[str]:
    """Command to launch the injector backend.

    Source runs: [python, main.py, ...]. Frozen exe runs: the sibling
    sni-backend.exe (a frozen GUI must not re-exec itself as backend).
    """
    if getattr(sys, "frozen", False):
        return [BACKEND_EXE, *args]
    return [sys.executable, MAIN_PATH, *args]


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


def _is_noise_line(line: str) -> bool:
    """True for harmless-but-spammy injector output that should not hit the console.

    Currently: Windows asyncio 'Cancelling an overlapped future failed'
    (WinError 6) + its traceback companion lines, emitted when relay
    sockets close with a sock_recv/sock_accept still pending.
    """
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


def parse_host_list(text: str, default_port: int) -> list[dict]:
    """Parse 'ip, ip:port, ...' separated by comma/space/newline."""
    out: list[dict] = []
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


def parse_sni_list(text: str) -> list[str]:
    parts = text.replace(",", " ").replace(";", " ").split()
    seen, out = set(), []
    for p in parts:
        p = p.strip()
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def list_profiles() -> list[str]:
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


class SpooferGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SNI Spoofing — GUI v3")
        self.root.geometry("940x740")
        self.root.minsize(860, 640)
        self.root.configure(bg=COLORS["bg"])

        self.font_title = ("Segoe UI", 13, "bold")
        self.font_h = ("Segoe UI", 10, "bold")
        self.font_n = ("Segoe UI", 9)
        self.font_mono = ("Consolas", 9)

        self.injector_proc: subprocess.Popen | None = None
        self.xray_proc: subprocess.Popen | None = None
        self.running = False
        self.manual_stop = False
        self.start_time: float | None = None
        self.msg_q: queue.Queue = queue.Queue()
        self.active_conns = 0
        self.total_conns = 0
        self.success_conns = 0
        self.failed_conns = 0
        self.success_rate = 0.0
        self.best_endpoint = ""
        self.restart_tries = 0
        self.log_file: str | None = None

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
        # new smart fields
        self.v_method = tk.StringVar(value=str(cfg.get("BYPASS_METHOD", "wrong_seq")))
        self.v_timeout = tk.StringVar(value=str(cfg.get("HANDSHAKE_TIMEOUT", 2.0)))
        self.v_maxconn = tk.StringVar(value=str(cfg.get("MAX_CONNECTIONS", 200)))
        self.v_autorestart = tk.BooleanVar(value=True)
        # Candidate pools from ip_list.txt / sni_list.txt (CIDR-aware).
        # These are the pools the Smart Tools rank; only the fastest few
        # are written into the config so the WinDivert filter stays small.
        try:
            self.file_endpoints: list[dict] = lists_mod.load_ip_list(
                IP_LIST_PATH, default_port=int(str(cfg.get("CONNECT_PORT", 443)) or 443))
        except Exception:
            self.file_endpoints = []
        try:
            self.file_snis: list[str] = lists_mod.load_sni_list(SNI_LIST_PATH)
        except Exception:
            self.file_snis = []
        cfg_eps = cfg.get("ENDPOINTS") or []
        cfg_snis = cfg.get("FAKE_SNIS") or []
        if len(cfg_eps) > 1:
            self.extra_eps_text = "; ".join(f"{e['ip']}:{e['port']}" for e in cfg_eps[1:3])
        elif self.file_endpoints:
            self.extra_eps_text = "; ".join(
                f"{e['ip']}:{e['port']}" for e in self.file_endpoints[:2])
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

        self._open_log_file()
        self.log("SNI Spoofing GUI v3 ready. Configure, then press START.", "info")
        if self.file_endpoints:
            self.log(f"Loaded {len(self.file_endpoints)} endpoint candidate(s) from ip_list.txt "
                     f"(sampled, max {MAX_FILE_ENDPOINTS} used).", "info")
        elif os.path.exists(IP_LIST_PATH):
            self.log("ip_list.txt found but no usable IPs/CIDRs parsed.", "warning")
        if self.file_snis:
            self.log(f"Loaded {len(self.file_snis)} SNI candidate(s) from sni_list.txt.", "info")
        elif os.path.exists(SNI_LIST_PATH):
            self.log("sni_list.txt found but no usable SNIs parsed.", "warning")
        if not is_admin():
            self.log("Not Administrator — injector (WinDivert) will fail until restart as admin.", "warning")
        else:
            self.log("Running as Administrator.", "success")
        err = check_pydivert()
        if err:
            self.log(f"{err} — run: pip install -r requirements.txt", "warning")
        if getattr(sys, "frozen", False):
            if not os.path.exists(BACKEND_EXE):
                self.log(f"sni-backend.exe not found at {BACKEND_EXE}", "error")
        elif not os.path.exists(MAIN_PATH):
            self.log(f"main.py not found at {MAIN_PATH}", "error")

    # -- layout ---------------------------------------------------
    def _build(self):
        header = tk.Frame(self.root, bg=COLORS["header"], height=60)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="SNI SPOOFING v3", font=self.font_title,
                 fg=COLORS["primary"], bg=COLORS["header"]).pack(side=tk.LEFT, padx=14)
        tk.Label(header, text="failover · scoreboard · split_seq · profiles",
                 font=self.font_n, fg=COLORS["muted"], bg=COLORS["header"]).pack(side=tk.LEFT)
        sf = tk.Frame(header, bg=COLORS["header"])
        sf.pack(side=tk.RIGHT, padx=14)
        self.status_dot = tk.Label(sf, text="●", font=("Segoe UI", 14),
                                   fg=COLORS["muted"], bg=COLORS["header"])
        self.status_dot.pack(side=tk.LEFT)
        self.status_lbl = tk.Label(sf, text="INACTIVE", font=("Segoe UI", 10, "bold"),
                                   fg=COLORS["muted"], bg=COLORS["header"])
        self.status_lbl.pack(side=tk.LEFT, padx=6)

        bar = tk.Frame(self.root, bg=COLORS["bg"])
        bar.pack(fill=tk.X, padx=12, pady=8)
        self.btn_start = tk.Button(bar, text="▶ START", command=self.start,
                                   bg=COLORS["primary"], fg="white",
                                   font=("Segoe UI", 10, "bold"), width=11,
                                   relief="flat", cursor="hand2")
        self.btn_start.pack(side=tk.LEFT, padx=4)
        self.btn_stop = tk.Button(bar, text="⏹ STOP", command=self.stop,
                                  bg=COLORS["danger"], fg="white",
                                  font=("Segoe UI", 10, "bold"), width=11,
                                  relief="flat", cursor="hand2", state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=4)
        tk.Button(bar, text="📋 COPY PROXY", command=self.copy_proxy,
                  bg=COLORS["card"], fg="white", font=("Segoe UI", 10, "bold"),
                  relief="flat", cursor="hand2").pack(side=tk.LEFT, padx=4)
        tk.Button(bar, text="⬆ RUN AS ADMIN", command=lambda: relaunch_as_admin(os.path.abspath(__file__)),
                  bg=COLORS["card"], fg="white", font=self.font_n,
                  relief="flat", cursor="hand2").pack(side=tk.RIGHT, padx=4)
        tk.Button(bar, text="💾 SAVE", command=self.save_only,
                  bg=COLORS["card"], fg="white", font=self.font_n,
                  relief="flat", cursor="hand2").pack(side=tk.RIGHT, padx=4)

        # profiles row
        prof = tk.Frame(self.root, bg=COLORS["bg"])
        prof.pack(fill=tk.X, padx=12, pady=(0, 6))
        tk.Label(prof, text="Profile", bg=COLORS["bg"], fg=COLORS["muted"],
                 font=self.font_n).pack(side=tk.LEFT, padx=4)
        self.v_profile = tk.StringVar(value="")
        self.cbo_profile = ttk.Combobox(prof, textvariable=self.v_profile, width=22,
                                        values=list_profiles())
        self.cbo_profile.pack(side=tk.LEFT, padx=4)
        tk.Button(prof, text="Load", command=self.profile_load,
                  bg=COLORS["card"], fg="white", font=self.font_n,
                  relief="flat", cursor="hand2").pack(side=tk.LEFT, padx=2)
        tk.Button(prof, text="Save", command=self.profile_save,
                  bg=COLORS["card"], fg="white", font=self.font_n,
                  relief="flat", cursor="hand2").pack(side=tk.LEFT, padx=2)
        tk.Button(prof, text="Delete", command=self.profile_delete,
                  bg=COLORS["card"], fg="white", font=self.font_n,
                  relief="flat", cursor="hand2").pack(side=tk.LEFT, padx=2)
        tk.Button(prof, text="↻", command=self.profile_refresh, width=3,
                  bg=COLORS["card"], fg="white", font=self.font_n,
                  relief="flat", cursor="hand2").pack(side=tk.LEFT, padx=2)

        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=False, padx=12)
        tab1 = tk.Frame(nb, bg=COLORS["card"])
        tab2 = tk.Frame(nb, bg=COLORS["card"])
        tab3 = tk.Frame(nb, bg=COLORS["card"])
        nb.add(tab1, text="  DPI Bypass  ")
        nb.add(tab2, text="  Proxy / Xray  ")
        nb.add(tab3, text="  Smart Tools  ")
        self._row(tab1, "Listen host", self.v_listen_host)
        self._row(tab1, "Listen port", self.v_listen_port, w=12)
        self._row(tab1, "Fake SNI (primary)", self.v_fake_sni)
        self._row(tab1, "Endpoint IP (primary)", self.v_endpoint_ip)
        self._row(tab1, "Endpoint port", self.v_endpoint_port, w=12)
        # advanced engine controls
        mrow = tk.Frame(tab1, bg=COLORS["card"])
        mrow.pack(fill=tk.X, padx=12, pady=3)
        tk.Label(mrow, text="Bypass method", width=16, anchor="w",
                 bg=COLORS["card"], fg=COLORS["muted"], font=self.font_n).pack(side=tk.LEFT)
        ttk.Combobox(mrow, textvariable=self.v_method, state="readonly", width=18,
                     values=list(cm.SUPPORTED_METHODS)).pack(side=tk.LEFT, padx=8)
        tk.Label(mrow, text="Timeout", bg=COLORS["card"], fg=COLORS["muted"],
                 font=self.font_n).pack(side=tk.LEFT, padx=(12, 2))
        tk.Entry(mrow, textvariable=self.v_timeout, bg=COLORS["input"], fg="white",
                 font=self.font_n, relief="flat", width=6).pack(side=tk.LEFT, padx=2, ipady=3)
        tk.Label(mrow, text="Max conn", bg=COLORS["card"], fg=COLORS["muted"],
                 font=self.font_n).pack(side=tk.LEFT, padx=(12, 2))
        tk.Entry(mrow, textvariable=self.v_maxconn, bg=COLORS["input"], fg="white",
                 font=self.font_n, relief="flat", width=7).pack(side=tk.LEFT, padx=2, ipady=3)
        tk.Checkbutton(mrow, text="Auto-restart", variable=self.v_autorestart,
                       bg=COLORS["card"], fg=COLORS["muted"], selectcolor=COLORS["card"],
                       font=self.font_n).pack(side=tk.LEFT, padx=12)

        self._row(tab1, "Extra endpoints", None, w=34, text_var_name="extra",
                  hint="ip[:port], comma separated — failover list")
        self._row(tab1, "Extra SNIs", None, w=34, text_var_name="snis",
                  hint="comma separated — rotated per connection")

        mrow2 = tk.Frame(tab2, bg=COLORS["card"])
        mrow2.pack(fill=tk.X, padx=12, pady=4)
        tk.Label(mrow2, text="Mode", width=16, anchor="w",
                 bg=COLORS["card"], fg=COLORS["muted"], font=self.font_n).pack(side=tk.LEFT)
        ttk.Combobox(mrow2, textvariable=self.v_mode, state="readonly", width=25,
                     values=["SNI Only", "Trojan + Xray"]).pack(side=tk.LEFT, padx=8)
        self._row(tab2, "SOCKS5 port", self.v_socks, w=12)
        self._row(tab2, "HTTP port", self.v_http, w=12)
        self._row(tab2, "Trojan password", self.v_password)
        self._row(tab2, "Transport", self.v_transport, w=12)
        self._row(tab2, "WS path", self.v_path)
        self._row(tab2, "WS host", self.v_host)

        # smart tab
        for txt, cmd in [
            ("⚡ Rank endpoints by latency (current fields)", self.smart_rank),
            ("🚀 Rank + use fastest endpoint (current fields)", self.smart_use_fastest),
            ("📂 Rank file endpoints from ip_list.txt", self.smart_rank_file),
            ("🚀 Rank files + use fastest (ip_list.txt + sni_list.txt)", self.smart_use_fastest_file),
            ("📶 Ping SNIs on primary endpoint (sni_list.txt)", self.smart_rank_snis),
            ("🏆 Ping SNIs + use best SNI to spoof", self.smart_use_best_sni),
            ("🔄 Reload ip_list.txt / sni_list.txt", self.smart_reload_lists),
            ("🔍 TLS reachability test (primary IP+SNI)", self.smart_tls_test),
            ("💓 Check local relay health", self.smart_health),
            ("🧪 Run engine self-test (no Admin needed)", self.smart_selftest),
            ("📝 Fill suggested SNIs/endpoints", self.smart_fill_suggestions),
        ]:
            tk.Button(tab3, text=txt, command=cmd, bg=COLORS["input"], fg="white",
                      font=self.font_n, relief="flat", cursor="hand2",
                      anchor="w").pack(fill=tk.X, padx=12, pady=3)
        tk.Label(tab3, text="Tests use plain TCP/TLS (no injector). DPI bypass success still depends on network.",
                 bg=COLORS["card"], fg=COLORS["muted"], font=self.font_n,
                 wraplength=780, justify=tk.LEFT).pack(fill=tk.X, padx=12, pady=6)

        stats = tk.Frame(self.root, bg=COLORS["bg"])
        stats.pack(fill=tk.X, padx=12, pady=(8, 0))
        self.lbl_active = tk.Label(stats, text="Active: 0", font=self.font_n, fg=COLORS["fg"], bg=COLORS["bg"])
        self.lbl_active.pack(side=tk.LEFT, padx=6)
        self.lbl_total = tk.Label(stats, text="Total: 0", font=self.font_n, fg=COLORS["fg"], bg=COLORS["bg"])
        self.lbl_total.pack(side=tk.LEFT, padx=6)
        self.lbl_okfail = tk.Label(stats, text="OK: 0 Fail: 0", font=self.font_n, fg=COLORS["muted"], bg=COLORS["bg"])
        self.lbl_okfail.pack(side=tk.LEFT, padx=6)
        self.lbl_best = tk.Label(stats, text="Best: —", font=self.font_n, fg=COLORS["muted"], bg=COLORS["bg"])
        self.lbl_best.pack(side=tk.LEFT, padx=6)
        self.lbl_uptime = tk.Label(stats, text="Uptime: —", font=self.font_n, fg=COLORS["muted"], bg=COLORS["bg"])
        self.lbl_uptime.pack(side=tk.RIGHT, padx=6)

        box = tk.Frame(self.root, bg=COLORS["bg"])
        box.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        h = tk.Frame(box, bg=COLORS["header"])
        h.pack(fill=tk.X)
        tk.Label(h, text="LIVE CONSOLE", font=self.font_h,
                 fg=COLORS["primary"], bg=COLORS["header"]).pack(side=tk.LEFT, padx=8, pady=4)
        tk.Button(h, text="CLEAR", command=self.clear_log,
                  bg=COLORS["card"], fg="white", relief="flat", cursor="hand2").pack(side=tk.RIGHT, padx=4, pady=2)
        tk.Button(h, text="EXPORT", command=self.export_log,
                  bg=COLORS["card"], fg="white", relief="flat", cursor="hand2").pack(side=tk.RIGHT, padx=4, pady=2)
        self.console = scrolledtext.ScrolledText(box, bg=COLORS["card"], fg=COLORS["fg"],
                                                 font=self.font_mono, relief="flat", wrap=tk.WORD, height=10)
        self.console.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
        for tag, col in (("info", COLORS["primary"]), ("success", COLORS["success"]),
                         ("warning", COLORS["warning"]), ("error", COLORS["danger"])):
            self.console.tag_config(tag, foreground=col)

    def _row(self, parent, label, var, w=34, text_var_name=None, hint=None):
        r = tk.Frame(parent, bg=COLORS["card"])
        r.pack(fill=tk.X, padx=12, pady=3)
        tk.Label(r, text=label, width=18, anchor="w", bg=COLORS["card"],
                 fg=COLORS["muted"], font=self.font_n).pack(side=tk.LEFT)
        if text_var_name == "extra":
            self.e_extra = tk.Entry(r, bg=COLORS["input"], fg="white",
                                    font=self.font_n, relief="flat", width=w)
            self.e_extra.insert(0, self.extra_eps_text)
            self.e_extra.pack(side=tk.LEFT, padx=8, ipady=3, fill=tk.X, expand=True)
        elif text_var_name == "snis":
            self.e_snis = tk.Entry(r, bg=COLORS["input"], fg="white",
                                   font=self.font_n, relief="flat", width=w)
            self.e_snis.insert(0, self.snis_text)
            self.e_snis.pack(side=tk.LEFT, padx=8, ipady=3, fill=tk.X, expand=True)
        elif var is not None:
            tk.Entry(r, textvariable=var, bg=COLORS["input"], fg="white",
                     font=self.font_n, relief="flat", width=w).pack(side=tk.LEFT, padx=8, ipady=3)
        if hint:
            tk.Label(r, text=hint, bg=COLORS["card"], fg=COLORS["muted"],
                     font=("Segoe UI", 8)).pack(side=tk.LEFT)

    # -- config ---------------------------------------------------
    def _collect(self) -> tuple[dict | None, str | None]:
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
        # listen-port busy check is a warning, not fatal (done at start)
        return cfg, None

    def save_only(self):
        cfg, err = self._collect()
        if err:
            messagebox.showerror("Invalid config", err)
            return
        cm.save(CONFIG_PATH, cfg)
        xray_cfg = build_xray_config(int(cfg["LISTEN_PORT"]), int(cfg["SOCKS5_PORT"]), int(cfg["HTTP_PORT"]),
                                     cfg["TROJAN_PASSWORD"], cfg["TRANSPORT"], cfg["WS_PATH"], cfg["WS_HOST"])
        save_json(XRAY_CONFIG_PATH, xray_cfg)
        self.log("Saved config.json (+.full.json) + xray_config.json", "success")

    # -- profiles -------------------------------------------------
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
        self.e_extra.insert(0, "; ".join(f"{e['ip']}:{e['port']}" for e in eps[1:3]))
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
            self.log(f"Profile saved: {name}", "success")
        except Exception as exc:
            messagebox.showerror("Profile", f"Save failed: {exc}")

    def profile_load(self):
        name = (self.v_profile.get() or "").strip()
        if not name:
            messagebox.showinfo("Profile", "Select or type a profile name first.")
            return
        path = os.path.join(PROFILES_DIR, name + ".json")
        if not os.path.exists(path):
            messagebox.showerror("Profile", f"Not found: {name}")
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            self.apply_cfg(cfg)
            self.log(f"Profile loaded: {name} (press SAVE to apply to config.json)", "success")
        except Exception as exc:
            messagebox.showerror("Profile", f"Load failed: {exc}")

    def profile_delete(self):
        name = (self.v_profile.get() or "").strip()
        if not name:
            return
        path = os.path.join(PROFILES_DIR, name + ".json")
        try:
            if os.path.exists(path):
                if messagebox.askyesno("Profile", f"Delete profile '{name}'?"):
                    os.remove(path)
                    self.profile_refresh()
                    self.log(f"Profile deleted: {name}", "warning")
        except Exception as exc:
            messagebox.showerror("Profile", f"Delete failed: {exc}")

    # -- smart tools ----------------------------------------------
    def _all_endpoints(self) -> list[dict]:
        cfg, _ = self._collect()
        if cfg:
            return cfg["ENDPOINTS"]
        return [{"ip": self.v_endpoint_ip.get().strip(), "port": 443}]

    def _run_bg(self, fn, *args):
        threading.Thread(target=fn, args=args, daemon=True).start()

    def smart_rank(self):
        eps = self._all_endpoints()
        self.log(f"Ranking {len(eps)} endpoint(s)...", "info")
        def job():
            ranked = smart.rank_endpoints(eps)
            for r in ranked:
                status = f"{r['latency_ms']}ms" if r["ok"] else "UNREACHABLE"
                self.msg_q.put(("log", "smart", f"{r['ip']}:{r['port']} -> {status}"))
            ok = [r for r in ranked if r["ok"]]
            self.msg_q.put(("log", "smart",
                            f"Best: {ok[0]['ip']}:{ok[0]['port']} ({ok[0]['latency_ms']}ms)" if ok else "No reachable endpoints!"))
        self._run_bg(job)

    def smart_use_fastest(self):
        eps = self._all_endpoints()
        self.log("Finding fastest endpoint...", "info")
        def job():
            ranked = smart.rank_endpoints(eps)
            ok = [r for r in ranked if r["ok"]]
            if not ok:
                self.msg_q.put(("log", "smart", "No reachable endpoints."))
                return
            best = ok[0]
            self.msg_q.put(("use_best", best))
            self.msg_q.put(("log", "smart", f"Using fastest: {best['ip']}:{best['port']}"))
        self._run_bg(job)

    def smart_rank_file(self):
        eps = list(self.file_endpoints or [])
        if not eps:
            self.log("ip_list.txt has no usable endpoints — check the file format (IP / IP:port / CIDR).", "warning")
            return
        self.log(f"Ranking {len(eps)} file endpoint(s) from ip_list.txt...", "info")

        def job():
            ranked = smart.rank_endpoints(eps)
            for r in ranked:
                status = f"{r['latency_ms']}ms" if r["ok"] else "UNREACHABLE"
                self.msg_q.put(("log", "smart", f"{r['ip']}:{r['port']} -> {status}"))
            ok = [r for r in ranked if r["ok"]]
            self.msg_q.put(("log", "smart",
                            f"Best file endpoint: {ok[0]['ip']}:{ok[0]['port']} ({ok[0]['latency_ms']}ms)"
                            if ok else "No reachable file endpoints! Edit ip_list.txt."))
        self._run_bg(job)

    def smart_use_fastest_file(self):
        eps = list(self.file_endpoints or [])
        if not eps:
            self.log("ip_list.txt has no usable endpoints.", "warning")
            return
        snis = list(self.file_snis or [])
        self.log(f"Ranking {len(eps)} file endpoint(s), will keep fastest {MAX_FILE_ENDPOINTS}...", "info")

        def job():
            ranked = smart.rank_endpoints(eps)
            ok = [r for r in ranked if r["ok"]]
            if not ok:
                self.msg_q.put(("log", "smart", "No reachable file endpoints."))
                return
            top = ok[:MAX_FILE_ENDPOINTS]
            best = top[0]
            extras = [{"ip": r["ip"], "port": r["port"]} for r in top[1:]]
            self.msg_q.put(("use_best_multi", {
                "best": best,
                "extras": extras,
                "snis": snis[:8],
            }))
            self.msg_q.put(("log", "smart",
                            f"Using fastest file endpoint: {best['ip']}:{best['port']} "
                            f"(+{len(extras)} failover, {len(snis[:8])} SNIs from sni_list.txt). Press SAVE/START."))
        self._run_bg(job)

    def _sni_candidates(self, limit: int = 60) -> list[str]:
        """SNIs to ping: sni_list.txt first, else the GUI SNI fields."""
        if self.file_snis:
            return list(self.file_snis[:limit])
        out = [self.v_fake_sni.get().strip()] + parse_sni_list(self.e_snis.get())
        return [s for s in out if s][:limit]

    def _primary_endpoint(self) -> tuple[str, int]:
        ip = self.v_endpoint_ip.get().strip()
        try:
            port = int(self.v_endpoint_port.get().strip() or 443)
        except ValueError:
            port = 443
        return ip, port

    def smart_rank_snis(self):
        ip, port = self._primary_endpoint()
        snis = self._sni_candidates()
        if not ip:
            self.log("Set a primary Endpoint IP first.", "warning")
            return
        if not snis:
            self.log("No SNIs to ping — fill sni_list.txt or the SNI fields.", "warning")
            return
        self.log(f"Pinging {len(snis)} SNI(s) on {ip}:{port} (TLS handshake)...", "info")

        def job():
            ranked = smart.rank_snis(ip, port, snis)
            for r in ranked[:20]:
                status = f"{r['latency_ms']}ms {r['tls_version']}" if r["ok"] else f"FAIL ({r['error'][:60]})"
                self.msg_q.put(("log", "smart", f"{r['sni']} -> {status}"))
            ok = [r for r in ranked if r["ok"]]
            self.msg_q.put(("log", "smart",
                            f"Best SNI: {ok[0]['sni']} ({ok[0]['latency_ms']}ms, {len(ok)}/{len(ranked)} OK)"
                            if ok else f"No SNI answered on {ip}:{port}! Try another endpoint."))
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
        self.log(f"Pinging {len(snis)} SNI(s) on {ip}:{port}, will use the fastest...", "info")

        def job():
            ranked = smart.rank_snis(ip, port, snis)
            ok = [r for r in ranked if r["ok"]]
            if not ok:
                self.msg_q.put(("log", "smart", f"No SNI answered on {ip}:{port}."))
                return
            best = ok[0]
            self.msg_q.put(("use_best_sni", best))
            self.msg_q.put(("log", "smart",
                            f"Best SNI to spoof: {best['sni']} ({best['latency_ms']}ms). Press SAVE/START."))
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
        self.log(f"Reloaded: {len(self.file_endpoints)} endpoint(s) from ip_list.txt, "
                 f"{len(self.file_snis)} SNI(s) from sni_list.txt.", "success")
        # Offer them in the fields if the fields are empty.
        try:
            if self.file_endpoints and not self.e_extra.get().strip():
                self.e_extra.delete(0, tk.END)
                self.e_extra.insert(0, "; ".join(
                    f"{e['ip']}:{e['port']}" for e in self.file_endpoints[:4]))
            if self.file_snis and not self.e_snis.get().strip():
                primary = self.v_fake_sni.get().strip()
                rest = [s for s in self.file_snis if s != primary][:4]
                self.e_snis.delete(0, tk.END)
                self.e_snis.insert(0, ", ".join(rest))
        except Exception:
            pass

    def smart_tls_test(self):
        ip = self.v_endpoint_ip.get().strip()
        try:
            port = int(self.v_endpoint_port.get().strip())
        except ValueError:
            port = 443
        sni = self.v_fake_sni.get().strip()
        self.log(f"TLS test {ip}:{port} SNI={sni} ...", "info")
        def job():
            res = smart.tls_handshake_test(ip, port, sni)
            if res["ok"]:
                self.msg_q.put(("log", "smart", f"TLS OK ({res['latency_ms']}ms, {res['tls_version']})"))
            else:
                self.msg_q.put(("log", "smart", f"TLS FAILED: {res['error']}"))
        self._run_bg(job)

    def smart_health(self):
        host = self.v_listen_host.get().strip() or "0.0.0.0"
        try:
            port = int(self.v_listen_port.get().strip())
        except ValueError:
            self.log("Bad listen port.", "error")
            return
        def job():
            free = smart.is_port_free("127.0.0.1", port)
            relay = smart.check_local_relay(host, port)
            self.msg_q.put(("log", "smart",
                            f"Listen port {port}: {'FREE (not running)' if free else 'IN USE'}; "
                            f"relay: {'ACCEPTING' if relay['ok'] else 'NOT ACCEPTING'}"))
        self._run_bg(job)

    def smart_fill_suggestions(self):
        if not self.e_extra.get().strip():
            if self.file_endpoints:
                self.e_extra.delete(0, tk.END)
                self.e_extra.insert(0, "; ".join(
                    f"{e['ip']}:{e['port']}" for e in self.file_endpoints[:4]))
            else:
                self.e_extra.delete(0, tk.END)
                self.e_extra.insert(0, "188.114.96.0:443, 104.21.0.0:443")
        if not self.e_snis.get().strip():
            if self.file_snis:
                primary = self.v_fake_sni.get().strip()
                rest = [s for s in self.file_snis if s != primary][:4]
                self.e_snis.delete(0, tk.END)
                self.e_snis.insert(0, ", ".join(rest or self.file_snis[:4]))
            else:
                self.e_snis.delete(0, tk.END)
                self.e_snis.insert(0, "cloudflare.com, cdn.jsdelivr.net")
        self.log(f"Suggestions: {len(self.file_endpoints)} file endpoint(s), "
                 f"{len(self.file_snis)} file SNI(s); built-ins={', '.join(smart.SUGGESTED_SNIS[:4])} ...", "info")

    def smart_selftest(self):
        self.log("Running engine self-test (no Admin needed)...", "info")

        def job():
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = subprocess.SW_HIDE
                kw = {"cwd": APP_DIR, "stdout": subprocess.PIPE, "stderr": subprocess.STDOUT,
                      "text": True, "timeout": 60}
                if sys.platform == "win32":
                    kw.update(startupinfo=si, creationflags=subprocess.CREATE_NO_WINDOW)
                cp = subprocess.run(backend_cmd("--self-test", "--config", CONFIG_PATH), **kw)
                out = (cp.stdout or "").strip()[-3000:]
                if cp.returncode == 0:
                    self.msg_q.put(("log", "selftest", "SELF-TEST PASSED"))
                else:
                    self.msg_q.put(("log", "selftest", f"SELF-TEST FAILED (exit {cp.returncode})"))
                for line in out.splitlines()[-25:]:
                    self.msg_q.put(("log", "selftest", line))
            except Exception as exc:
                self.msg_q.put(("log", "selftest", f"self-test error: {exc}"))

        self._run_bg(job)

    # -- process control ------------------------------------------
    def start(self):
        if self.running:
            self.log("Already running.", "warning")
            return
        cfg, err = self._collect()
        if err:
            messagebox.showerror("Invalid config", err)
            self.log(f"Invalid config: {err}", "error")
            return
        if getattr(sys, "frozen", False):
            if not os.path.exists(BACKEND_EXE):
                messagebox.showerror("Missing file", f"sni-backend.exe not found:\n{BACKEND_EXE}")
                return
        elif not os.path.exists(MAIN_PATH):
            messagebox.showerror("Missing file", f"main.py not found:\n{MAIN_PATH}")
            return
        try:
            lp = int(cfg["LISTEN_PORT"])
            if not smart.is_port_free("127.0.0.1", lp):
                if not messagebox.askyesno("Port busy",
                        f"Port {lp} seems IN USE. Start anyway?"):
                    return
        except Exception:
            pass
        if not is_admin():
            if not messagebox.askyesno("Not admin",
                    "You are NOT Administrator. WinDivert will likely fail.\nStart anyway?"):
                return
        self.save_only()
        cfg, err = self._collect()
        if err:
            return
        eps = ", ".join(f"{e['ip']}:{e['port']}" for e in cfg["ENDPOINTS"][:4])
        self.log(f"Starting: {cfg['LISTEN_HOST']}:{cfg['LISTEN_PORT']} -> [{eps}] "
                 f"(SNI={cfg['FAKE_SNIS'][0]}, method={cfg['BYPASS_METHOD']})", "info")
        try:
            self.manual_stop = False
            self.restart_tries = 0
            self.injector_proc = self._spawn(backend_cmd("--config", CONFIG_PATH))
        except Exception as exc:
            self.log(f"Failed to start injector: {exc}", "error")
            return
        if cfg["MODE"] == "Trojan + Xray":
            xray_exe = os.path.join(APP_DIR, "xray.exe")
            if not os.path.exists(xray_exe):
                self.log("xray.exe not found — running SNI injector only.", "warning")
            else:
                try:
                    self.xray_proc = self._spawn([xray_exe, "-c", XRAY_CONFIG_PATH])
                    self.log(f"Xray started (SOCKS5 :{cfg['SOCKS5_PORT']}, HTTP :{cfg['HTTP_PORT']})", "success")
                except Exception as exc:
                    self.log(f"Xray start failed: {exc}", "warning")
        self.running = True
        self.start_time = time.time()
        self.active_conns = self.total_conns = self.success_conns = self.failed_conns = 0
        self.success_rate = 0.0
        self.best_endpoint = ""
        self._refresh_stats()
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self._set_status(True)
        threading.Thread(target=self._reader, args=(self.injector_proc, "injector"), daemon=True).start()
        if self.xray_proc:
            threading.Thread(target=self._reader, args=(self.xray_proc, "xray"), daemon=True).start()
        self.log("Injector started.", "success")

    def _spawn(self, cmd: list[str]) -> subprocess.Popen:
        if sys.platform == "win32":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            return subprocess.Popen(cmd, cwd=APP_DIR, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1,
                                    startupinfo=si, creationflags=subprocess.CREATE_NO_WINDOW)
        return subprocess.Popen(cmd, cwd=APP_DIR, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)

    def _reader(self, proc: subprocess.Popen, tag: str):
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
            self.msg_q.put(("log", tag, f"[{tag}] reader error: {exc}"))
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
                    except Exception:
                        pass
                    self._refresh_stats()
                elif kind == "use_best":
                    _, best = msg
                    self.v_endpoint_ip.set(best["ip"])
                    self.v_endpoint_port.set(str(best["port"]))
                    self._append(f"Primary endpoint set to {best['ip']}:{best['port']}", "success")
                elif kind == "use_best_multi":
                    _, payload = msg
                    best = payload.get("best", {})
                    extras = payload.get("extras", []) or []
                    snis = payload.get("snis", []) or []
                    if best.get("ip"):
                        self.v_endpoint_ip.set(best["ip"])
                        self.v_endpoint_port.set(str(best.get("port", 443)))
                    try:
                        self.e_extra.delete(0, tk.END)
                        self.e_extra.insert(0, "; ".join(
                            f"{e['ip']}:{e['port']}" for e in extras[: MAX_FILE_ENDPOINTS - 1]))
                    except Exception:
                        pass
                    try:
                        if snis:
                            primary = self.v_fake_sni.get().strip()
                            if primary not in snis:
                                self.v_fake_sni.set(snis[0])
                                rest = snis[1:5]
                            else:
                                rest = [s for s in snis if s != primary][:4]
                            self.e_snis.delete(0, tk.END)
                            self.e_snis.insert(0, ", ".join(rest))
                    except Exception:
                        pass
                    self._append(f"Primary endpoint set to {best.get('ip')}:{best.get('port')} "
                                 f"(+{len(extras)} failover from ip_list.txt, {len(snis)} SNIs from sni_list.txt)",
                                 "success")
                elif kind == "use_best_sni":
                    _, best = msg
                    sni = str(best.get("sni", "") or "").strip()
                    if sni:
                        self.v_fake_sni.set(sni)
                    self._append(f"Fake SNI set to {sni} "
                                 f"({best.get('latency_ms')}ms on primary endpoint)", "success")
                elif kind == "log":
                    _, tag, line = msg
                    low = line.lower()
                    if "error" in low or "fatal" in low or "traceback" in low:
                        lvl = "error"
                    elif "warn" in low:
                        lvl = "warning"
                    elif "success" in low or "started" in low or "ok (" in low or "tls ok" in low:
                        lvl = "success"
                    else:
                        lvl = "info"
                    self._append(f"[{tag}] {line}", lvl)
                    low_tag = str(tag).lower()
                    if low_tag == "injector" and ("windivert" in low or "access is denied" in low):
                        self._append("[gui] WinDivert failed — run GUI as Administrator "
                                     "(⬆ RUN AS ADMIN) and press START again.", "error")
                elif kind == "exit":
                    _, tag = msg
                    self._append(f"[{tag}] process exited.", "warning")
                    if tag == "injector" and self.running and not self.manual_stop:
                        self.root.after(0, self._on_injector_exit)
        except queue.Empty:
            pass
        if self.running and self.start_time:
            secs = int(time.time() - self.start_time)
            self.lbl_uptime.config(text=f"Uptime: {secs // 60:02d}:{secs % 60:02d}")
        self.root.after(120, self._poll_queue)

    def _refresh_stats(self):
        self.lbl_active.config(text=f"Active: {self.active_conns}")
        self.lbl_total.config(text=f"Total: {self.total_conns}")
        self.lbl_okfail.config(text=f"OK: {self.success_conns} Fail: {self.failed_conns}")
        best = self.best_endpoint or "—"
        self.lbl_best.config(text=f"Best: {best} ({self.success_rate:.0%})")

    def _on_injector_exit(self):
        if self.manual_stop or not self.running:
            return
        # crash? maybe auto-restart
        if self.v_autorestart.get() and self.restart_tries < 3:
            self.restart_tries += 1
            self.log(f"Injector crashed — auto-restart {self.restart_tries}/3 in 2s...", "warning")
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
        self.log("Injector exited — port in use? not admin? WinDivert? (disable Auto-restart to stop retrying)", "error")

    def _do_restart(self):
        if self.manual_stop or self.running:
            return
        # reset buttons then call start()
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self._set_status(False)
        self.start()
        # start() resets restart_tries — restore counter
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
        self.lbl_uptime.config(text="Uptime: —")
        self.log("Stopped.", "warning")

    @staticmethod
    def _terminate(proc: subprocess.Popen | None):
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

    # -- misc UI --------------------------------------------------
    def _set_status(self, on: bool):
        if on:
            self.status_dot.config(fg=COLORS["success"])
            self.status_lbl.config(text="ACTIVE", fg=COLORS["success"])
        else:
            self.status_dot.config(fg=COLORS["muted"])
            self.status_lbl.config(text="INACTIVE", fg=COLORS["muted"])

    def log(self, text: str, level: str = "info"):
        self.msg_q.put(("log", "gui", text))

    def _append(self, text: str, level: str):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {text}\n"
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
            self.log_file = os.path.join(LOGS_DIR, f"gui_{datetime.now():%Y%m%d}.log")
        except Exception:
            self.log_file = None

    def clear_log(self):
        self.console.delete("1.0", tk.END)

    def export_log(self):
        try:
            name = os.path.join(APP_DIR, f"sni_log_{datetime.now():%Y%m%d_%H%M%S}.txt")
            with open(name, "w", encoding="utf-8") as f:
                f.write(self.console.get("1.0", tk.END))
            self._append(f"Log exported: {name}", "success")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def copy_proxy(self):
        info = f"SOCKS5: 127.0.0.1:{self.v_socks.get().strip()}\nHTTP: 127.0.0.1:{self.v_http.get().strip()}"
        self.root.clipboard_clear()
        self.root.clipboard_append(info)
        self._append("Proxy info copied to clipboard.", "success")

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
    try:
        style = ttk.Style()
        if sys.platform == "win32":
            try:
                style.theme_use("clam")
            except Exception:
                pass
    except Exception:
        pass
    SpooferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
