# sni_spoofer_gui.py
# SNI Spoofing Tool v4.0 - Modern UI
# Original Creator: Patterniha
# UI/Structure Modernization by Xenon using DeepSeek AI

import sys
import os
import traceback
import ctypes
import json
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime

ERROR_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui_crash.log")
try:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    os.chdir(APP_DIR)

    # Admin check
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def run_as_admin():
        if not is_admin():
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()

    run_as_admin()

    CONFIG_PATH = os.path.join(APP_DIR, "config.json")
    injector_process = None
    injector_running = False

    # Colors (Windows 10 Dark Mode)
    COLORS = {
        'bg_window': '#202020',
        'bg_card': '#2D2D30',
        'bg_input': '#3C3C3C',
        'bg_header': '#252526',
        'primary': '#0078D4',
        'success': '#6B8E23',
        'danger': '#D32F2F',
        'warning': '#FF8C00',
        'text_white': '#FFFFFF',
        'text_gray': '#CCCCCC',
        'text_dim': '#999999'
    }

    class SNISpoofingGUI:
        def __init__(self):
            self.root = tk.Tk()
            self.root.title("SNI Spoofing v4.0 — Patterniha · Modified by Xenon using DeepSeek")
            self.root.geometry("950x700")
            self.root.minsize(850, 600)
            self.root.configure(bg=COLORS['bg_window'])
            
            # Fonts
            self.font_title = ("Segoe UI", 14, "bold")
            self.font_heading = ("Segoe UI", 11, "bold")
            self.font_normal = ("Segoe UI", 9)
            self.font_mono = ("Consolas", 9)
            
            # Variables
            self.mode = tk.StringVar(value="SNI Only")
            self.fake_sni = tk.StringVar(value="auth.vercel.com")
            self.custom_sni = tk.StringVar(value="auth.vercel.com")
            self.endpoint_ip = tk.StringVar(value="188.114.98.0")
            self.port = tk.StringVar(value="443")
            self.trojan_password = tk.StringVar(value="humanity")
            self.server_sni = tk.StringVar(value="www.creationlong.org")
            self.transport = tk.StringVar(value="ws")
            self.path = tk.StringVar(value="/assignment")
            self.host = tk.StringVar(value="www.creationlong.org")
            self.socks5_port = tk.StringVar(value="10808")
            self.http_port = tk.StringVar(value="10809")
            
            self.load_config()
            self.create_widgets()
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            
            self.log("✓ Administrator mode", "success")
            self.log("✓ SNI Spoofing Tool v4.0 — Original by Patterniha", "info")
            self.log("✓ Modern UI & Structure by Xenon using DeepSeek AI", "info")
        
        def load_config(self):
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, 'r') as f:
                    cfg = json.load(f)
                    self.endpoint_ip.set(cfg.get("CONNECT_IP", "188.114.98.0"))
                    self.port.set(str(cfg.get("CONNECT_PORT", 443)))
                    self.fake_sni.set(cfg.get("FAKE_SNI", "auth.vercel.com"))
        
        def save_config(self):
            cfg = {
                "LISTEN_HOST": "0.0.0.0",
                "LISTEN_PORT": 40443,
                "CONNECT_IP": self.endpoint_ip.get().strip(),
                "CONNECT_PORT": int(self.port.get().strip()),
                "FAKE_SNI": self.fake_sni.get().strip()
            }
            with open(CONFIG_PATH, 'w') as f:
                json.dump(cfg, f, indent=2)
        
        def create_xray_config(self):
            config = {
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {"port": int(self.socks5_port.get()), "protocol": "socks", "settings": {"udp": True, "auth": "noauth"}, "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
                    {"port": int(self.http_port.get()), "protocol": "http", "settings": {"accounts": [], "allowTransparent": False}, "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}}
                ],
                "outbounds": [
                    {"protocol": "trojan", "settings": {"servers": [{"address": "127.0.0.1", "port": 40443, "password": self.trojan_password.get()}]}, "streamSettings": {"network": self.transport.get(), "wsSettings": {"path": self.path.get(), "headers": {"Host": self.host.get()}}}},
                    {"protocol": "freedom", "tag": "direct", "settings": {}}
                ],
                "routing": {"rules": [{"type": "field", "outboundTag": "direct", "domain": ["geosite:cn"]}]}
            }
            with open(os.path.join(APP_DIR, "xray_config.json"), "w") as f:
                json.dump(config, f, indent=2)
        
        def on_mode_change(self, event=None):
            self.log(f"Mode changed to: {self.mode.get()}", "info")
            self.create_xray_config()
            if self.mode.get() == "SNI Only":
                self.trojan_frame.pack_forget()
            else:
                self.trojan_frame.pack(fill=tk.X, pady=(0, 10))
        
        def copy_to_clipboard(self, text):
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Copied", "✓ Copied to clipboard")
        
        def copy_proxy_info(self):
            info = f"SOCKS5: 127.0.0.1:{self.socks5_port.get()}\nHTTP: 127.0.0.1:{self.http_port.get()}"
            self.copy_to_clipboard(info)
        
        def log(self, message, level="info"):
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_line = f"[{timestamp}] {message}\n"
            colors = {'success': COLORS['success'], 'error': COLORS['danger'], 'warning': COLORS['warning'], 'info': COLORS['primary']}
            def _log():
                self.log_text.insert(tk.END, log_line)
                start = self.log_text.index("end-2l")
                end = self.log_text.index("end-1c")
                self.log_text.tag_add(level, start, end)
                self.log_text.tag_config(level, foreground=colors.get(level, COLORS['text_gray']))
                self.log_text.see(tk.END)
            if threading.current_thread() is threading.main_thread():
                _log()
            else:
                self.root.after(0, _log)
        
        def clear_log(self):
            self.log_text.delete(1.0, tk.END)
            self.log("Log cleared", "info")
        
        def export_log(self):
            try:
                filename = f"sni_spoofing_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                self.log(f"Log exported to {filename}", "success")
            except Exception as e:
                self.log(f"Export failed: {e}", "error")
        
        def update_status(self, running):
            if running:
                self.status_dot.config(text="●", fg=COLORS['success'])
                self.status_text.config(text="ACTIVE", fg=COLORS['success'])
            else:
                self.status_dot.config(text="●", fg=COLORS['text_dim'])
                self.status_text.config(text="INACTIVE", fg=COLORS['text_gray'])
        
        def run_xray(self):
            try:
                xray_path = os.path.join(APP_DIR, "xray.exe")
                if not os.path.exists(xray_path):
                    self.log("⚠ xray.exe not found", "warning")
                    return
                if sys.platform == "win32":
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE
                    subprocess.Popen([xray_path, "-c", "xray_config.json"], cwd=APP_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, startupinfo=startupinfo, creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    subprocess.Popen([xray_path, "-c", "xray_config.json"], cwd=APP_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.log(f"✅ Xray started — SOCKS5: {self.socks5_port.get()} | HTTP: {self.http_port.get()}", "success")
            except Exception as e:
                self.log(f"⚠ Xray error: {e}", "warning")
        
        def start_injection(self):
            global injector_process, injector_running
            try:
                self.save_config()
                self.create_xray_config()
                if injector_running:
                    self.log("⚠ Already running", "warning")
                    return
                
                self.log("🚀 Starting packet injector...", "info")
                main_path = os.path.join(APP_DIR, "main.py")
                if not os.path.exists(main_path):
                    self.log(f"❌ main.py not found at {main_path}", "error")
                    messagebox.showerror("Error", f"main.py not found!\n{main_path}")
                    return
                
                if sys.platform == "win32":
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE
                    injector_process = subprocess.Popen([sys.executable, main_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=APP_DIR, startupinfo=startupinfo, creationflags=subprocess.CREATE_NO_WINDOW, text=True)
                else:
                    injector_process = subprocess.Popen([sys.executable, main_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=APP_DIR, text=True)
                
                injector_running = True
                self.start_btn.config(state=tk.DISABLED)
                self.stop_btn.config(state=tk.NORMAL)
                self.update_status(True)
                self.log("✅ Injector started successfully", "success")
                self.log(f"🌐 Listening on 0.0.0.0:40443", "info")
                self.log(f"🎭 Fake SNI: {self.fake_sni.get()}", "info")
                self.log(f"🔗 Endpoint: {self.endpoint_ip.get()}:{self.port.get()}", "info")
                
                if self.mode.get() != "SNI Only":
                    self.run_xray()
                
                def read_output():
                    global injector_running
                    while injector_running and injector_process:
                        try:
                            line = injector_process.stdout.readline()
                            if not line:
                                break
                            line = line.strip()
                            if line:
                                if "error" in line.lower():
                                    self.log(line, "error")
                                elif "success" in line.lower():
                                    self.log(line, "success")
                                elif "warning" in line.lower():
                                    self.log(line, "warning")
                                else:
                                    self.log(line, "info")
                        except:
                            break
                    injector_running = False
                    self.root.after(0, self._reset_ui)
                
                threading.Thread(target=read_output, daemon=True).start()
                
            except Exception as e:
                self.log(f"❌ Start failed: {e}", "error")
                messagebox.showerror("Error", str(e))
        
        def _reset_ui(self):
            global injector_running
            injector_running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.update_status(False)
            self.log("⏹ Injector stopped", "warning")
        
        def stop_injection(self):
            global injector_process, injector_running
            if not injector_running:
                return
            self.log("🛑 Stopping injector...", "warning")
            try:
                if injector_process:
                    injector_process.terminate()
                    try:
                        injector_process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        injector_process.kill()
                injector_running = False
                self._reset_ui()
            except Exception as e:
                self.log(f"❌ Stop error: {e}", "error")
        
        def on_closing(self):
            if injector_running:
                if messagebox.askyesno("Exit", "Injector is running. Stop and exit?"):
                    self.stop_injection()
                    self.root.destroy()
            else:
                self.root.destroy()
        
        def create_widgets(self):
            self.root.grid_rowconfigure(0, weight=0)  # header
            self.root.grid_rowconfigure(1, weight=0)  # control bar
            self.root.grid_rowconfigure(2, weight=3)  # settings
            self.root.grid_rowconfigure(3, weight=2)  # log
            self.root.grid_columnconfigure(0, weight=1)
            
            # Header
            header = tk.Frame(self.root, bg=COLORS['bg_header'], height=70)
            header.grid(row=0, column=0, sticky="ew")
            header.grid_propagate(False)
            
            title_frame = tk.Frame(header, bg=COLORS['bg_header'])
            title_frame.place(x=15, y=12)
            tk.Label(title_frame, text="SNI SPOOFING", font=self.font_title, fg=COLORS['primary'], bg=COLORS['bg_header']).pack(anchor="w")
            tk.Label(title_frame, text="Original by Patterniha · Modernized by Xenon (DeepSeek)", font=("Segoe UI", 9), fg=COLORS['text_gray'], bg=COLORS['bg_header']).pack(anchor="w")
            
            # Status indicator
            status_frame = tk.Frame(header, bg=COLORS['bg_header'])
            status_frame.pack(side=tk.RIGHT, padx=20, pady=15)
            self.status_dot = tk.Label(status_frame, text="●", font=("Segoe UI", 14), fg=COLORS['text_dim'], bg=COLORS['bg_header'])
            self.status_dot.pack(side=tk.LEFT)
            self.status_text = tk.Label(status_frame, text="INACTIVE", font=("Segoe UI", 10, "bold"), fg=COLORS['text_gray'], bg=COLORS['bg_header'])
            self.status_text.pack(side=tk.LEFT, padx=5)
            
            # Control bar
            control_bar = tk.Frame(self.root, bg=COLORS['bg_window'], pady=10)
            control_bar.grid(row=1, column=0, sticky="ew", padx=15)
            self.start_btn = tk.Button(control_bar, text="▶ START", command=self.start_injection, bg=COLORS['primary'], fg="white", font=("Segoe UI", 11, "bold"), width=12, relief="flat", cursor="hand2")
            self.start_btn.pack(side=tk.LEFT, padx=5)
            self.stop_btn = tk.Button(control_bar, text="⏹ STOP", command=self.stop_injection, bg=COLORS['danger'], fg="white", font=("Segoe UI", 11, "bold"), width=12, relief="flat", cursor="hand2", state=tk.DISABLED)
            self.stop_btn.pack(side=tk.LEFT, padx=5)
            tk.Button(control_bar, text="📋 COPY PROXY", command=self.copy_proxy_info, bg=COLORS['bg_card'], fg=COLORS['text_white'], font=("Segoe UI", 11, "bold"), width=14, relief="flat", cursor="hand2").pack(side=tk.LEFT, padx=5)
            
            # Settings area (scrollable)
            settings_container = tk.Frame(self.root, bg=COLORS['bg_window'])
            settings_container.grid(row=2, column=0, sticky="nsew", padx=15, pady=(0,10))
            settings_container.grid_rowconfigure(0, weight=1)
            settings_container.grid_columnconfigure(0, weight=1)
            
            canvas = tk.Canvas(settings_container, bg=COLORS['bg_window'], highlightthickness=0)
            scrollbar = ttk.Scrollbar(settings_container, orient="vertical", command=canvas.yview)
            scrollable = tk.Frame(canvas, bg=COLORS['bg_window'])
            canvas.configure(yscrollcommand=scrollbar.set)
            canvas_window = canvas.create_window((0,0), window=scrollable, anchor="nw", width=900)
            scrollable.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas_window, width=e.width))
            canvas.grid(row=0, column=0, sticky="nsew")
            scrollbar.grid(row=0, column=1, sticky="ns")
            
            # DPI Bypass card
            dpi_card = tk.LabelFrame(scrollable, text=" DPI BYPASS SETTINGS ", bg=COLORS['bg_card'], fg=COLORS['primary'], font=self.font_heading, padx=15, pady=10, bd=1, relief="solid")
            dpi_card.pack(fill=tk.X, pady=(0,10))
            
            def add_row(parent, label, var, width=40):
                row = tk.Frame(parent, bg=COLORS['bg_card'])
                row.pack(fill=tk.X, pady=5)
                tk.Label(row, text=label, width=18, anchor="w", bg=COLORS['bg_card'], fg=COLORS['text_gray'], font=self.font_normal).pack(side=tk.LEFT)
                tk.Entry(row, textvariable=var, bg=COLORS['bg_input'], fg=COLORS['text_white'], font=self.font_normal, relief="flat", width=width, bd=0).pack(side=tk.LEFT, padx=10, pady=3)
            
            mode_row = tk.Frame(dpi_card, bg=COLORS['bg_card'])
            mode_row.pack(fill=tk.X, pady=5)
            tk.Label(mode_row, text="Mode", width=18, anchor="w", bg=COLORS['bg_card'], fg=COLORS['text_gray'], font=self.font_normal).pack(side=tk.LEFT)
            mode_combo = ttk.Combobox(mode_row, textvariable=self.mode, values=["SNI Only", "Trojan Mode", "Full TLS"], width=37)
            mode_combo.pack(side=tk.LEFT, padx=10)
            mode_combo.bind('<<ComboboxSelected>>', self.on_mode_change)
            
            add_row(dpi_card, "Fake SNI", self.fake_sni, 40)
            add_row(dpi_card, "Custom SNI", self.custom_sni, 40)
            add_row(dpi_card, "CDN / Endpoint IP", self.endpoint_ip, 40)
            add_row(dpi_card, "Port", self.port, 15)
            
            # Proxy Output card
            proxy_card = tk.LabelFrame(scrollable, text=" PROXY OUTPUT ", bg=COLORS['bg_card'], fg=COLORS['primary'], font=self.font_heading, padx=15, pady=10, bd=1, relief="solid")
            proxy_card.pack(fill=tk.X, pady=(0,10))
            
            socks_row = tk.Frame(proxy_card, bg=COLORS['bg_card'])
            socks_row.pack(fill=tk.X, pady=5)
            tk.Label(socks_row, text="SOCKS5 Port", width=18, anchor="w", bg=COLORS['bg_card'], fg=COLORS['text_gray']).pack(side=tk.LEFT)
            tk.Entry(socks_row, textvariable=self.socks5_port, bg=COLORS['bg_input'], fg=COLORS['text_white'], width=15, relief="flat", bd=0).pack(side=tk.LEFT, padx=10, pady=3)
            tk.Button(socks_row, text="📋", command=lambda: self.copy_to_clipboard(f"127.0.0.1:{self.socks5_port.get()}"), bg=COLORS['bg_input'], fg=COLORS['primary'], relief="flat", cursor="hand2", width=3).pack(side=tk.LEFT, padx=5)
            
            http_row = tk.Frame(proxy_card, bg=COLORS['bg_card'])
            http_row.pack(fill=tk.X, pady=5)
            tk.Label(http_row, text="HTTP Port", width=18, anchor="w", bg=COLORS['bg_card'], fg=COLORS['text_gray']).pack(side=tk.LEFT)
            tk.Entry(http_row, textvariable=self.http_port, bg=COLORS['bg_input'], fg=COLORS['text_white'], width=15, relief="flat", bd=0).pack(side=tk.LEFT, padx=10, pady=3)
            tk.Button(http_row, text="📋", command=lambda: self.copy_to_clipboard(f"127.0.0.1:{self.http_port.get()}"), bg=COLORS['bg_input'], fg=COLORS['primary'], relief="flat", cursor="hand2", width=3).pack(side=tk.LEFT, padx=5)
            
            # Trojan card
            self.trojan_frame = tk.LabelFrame(scrollable, text=" V2RAY / TROJAN ", bg=COLORS['bg_card'], fg=COLORS['primary'], font=self.font_heading, padx=15, pady=10, bd=1, relief="solid")
            if self.mode.get() != "SNI Only":
                self.trojan_frame.pack(fill=tk.X, pady=(0,10))
            add_row(self.trojan_frame, "Password", self.trojan_password, 30)
            add_row(self.trojan_frame, "Server SNI", self.server_sni, 30)
            add_row(self.trojan_frame, "Transport", self.transport, 15)
            add_row(self.trojan_frame, "Path", self.path, 30)
            add_row(self.trojan_frame, "Host", self.host, 30)
            
            # Footer
            footer = tk.Frame(scrollable, bg=COLORS['bg_window'], height=35)
            footer.pack(fill=tk.X, pady=(10,5))
            usdt = tk.Label(footer, text="💰 USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424", fg=COLORS['warning'], bg=COLORS['bg_window'], cursor="hand2", font=self.font_normal)
            usdt.pack(side=tk.LEFT)
            usdt.bind("<Button-1>", lambda e: self.copy_to_clipboard("0x76a768B53Ca77B43086946315f0BDF21156bF424"))
            tk.Label(footer, text="© 2026 Patterniha · Modernization by Xenon using DeepSeek", fg=COLORS['text_dim'], bg=COLORS['bg_window'], font=self.font_normal).pack(side=tk.RIGHT)
            
            # Log area
            log_container = tk.Frame(self.root, bg=COLORS['bg_window'])
            log_container.grid(row=3, column=0, sticky="nsew", padx=15, pady=(0,15))
            log_container.grid_rowconfigure(0, weight=0)
            log_container.grid_rowconfigure(1, weight=1)
            log_container.grid_columnconfigure(0, weight=1)
            
            log_header = tk.Frame(log_container, bg=COLORS['bg_header'], height=35)
            log_header.grid(row=0, column=0, sticky="ew")
            log_header.grid_propagate(False)
            tk.Label(log_header, text="LIVE CONSOLE", font=self.font_heading, fg=COLORS['primary'], bg=COLORS['bg_header']).pack(side=tk.LEFT, padx=10)
            tk.Button(log_header, text="🗑 CLEAR", command=self.clear_log, bg=COLORS['bg_card'], fg=COLORS['text_white'], relief="flat", cursor="hand2").pack(side=tk.RIGHT, padx=5, pady=3)
            tk.Button(log_header, text="💾 EXPORT", command=self.export_log, bg=COLORS['bg_card'], fg=COLORS['text_white'], relief="flat", cursor="hand2").pack(side=tk.RIGHT, padx=5, pady=3)
            
            self.log_text = scrolledtext.ScrolledText(log_container, bg=COLORS['bg_card'], fg=COLORS['text_white'], font=self.font_mono, relief="flat", wrap=tk.WORD, insertbackground=COLORS['primary'])
            self.log_text.grid(row=1, column=0, sticky="nsew", pady=5)
            
            self.log_text.tag_config("success", foreground=COLORS['success'])
            self.log_text.tag_config("error", foreground=COLORS['danger'])
            self.log_text.tag_config("warning", foreground=COLORS['warning'])
            self.log_text.tag_config("info", foreground=COLORS['primary'])
    
    if __name__ == "__main__":
        app = SNISpoofingGUI()
        app.root.mainloop()

except Exception as e:
    with open(ERROR_LOG, "w") as f:
        f.write(traceback.format_exc())
    messagebox.showerror("Critical Error", f"GUI crashed!\nError saved to:\n{ERROR_LOG}\n\n{e}")
    input("Press Enter to exit...")
