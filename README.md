SNI Spoofing v2 (gui v3) — DPI bypass via fake-SNI injection (WinDivert).

Original by Patterniha. GUI v2: smarter + stronger engine.

## Run

```bat
pip install -r requirements.txt
python gui.py        :: Windows, Run as Administrator
python run.py        :: launcher (no console window)
```

## Windows 7 .exe builds (32-bit + 64-bit)

Ready zips (keep all files in one folder, run `SNI-Spoofer.exe` as Admin):

- `SNI-Spoofer-win32-win7.zip` — 32-bit (runs on 32- and 64-bit Windows 7 SP1+)
- `SNI-Spoofer-win64-win7.zip` — 64-bit (64-bit Windows 7 SP1+ only)

Rebuild (needs the matching interpreter + offline wheels, see `build_exe.py`):

```bat
C:\Python38-x86\python.exe build_exe.py --dist dist-win32
C:\Python38-x64\python.exe build_exe.py --dist dist-win64
```

Built with Python 3.8.10 + PyInstaller 4.10 (Win7 bootloader) + pydivert
2.1.0 (WinDivert 2.2 driver). Both exes request elevation via manifest.

`main.py` (injector) can also run headless:

```bat
python main.py --config config.json --log-level INFO
```

Requires Windows + Administrator + WinDivert (`pip install pydivert` installs it).

## What's new in v2

Smarter:

- Multi-endpoint failover (`ENDPOINTS` list, round-robin + fallback per connection).
- Multi-SNI rotation (`FAKE_SNIS`, random per connection).
- GUI Smart Tools: rank endpoints by TCP latency, use-fastest, TLS reachability
  test, local relay health check, suggested SNIs/endpoints.
- Shared config schema (`utils/config_manager.py`, v1 auto-migrates to v2).

Stronger:

- Stats leak fixed: `active` now decrements on success AND failure; new
  `success`/`failed` counters + `get_snapshot()` (GUI shows OK/Fail + uptime).
- `fake_tcp.py` never `sys.exit()`s on a bad packet — per-packet guard, graceful
  close, `SUPPORTED_METHODS = (wrong_seq, wrong_seq_ttl)`.
- `main.py`: connection limit semaphore (`MAX_CONNECTIONS`), configurable
  `HANDSHAKE_TIMEOUT`, graceful shutdown (no more `sys.exit` in handlers/relays),
  WinDivert filter covers ALL endpoints, `--log-level`.
- GUI: listen-port busy check, invalid-config blocks start, auto-restart on
  injector crash (3 tries, toggleable), bounded log buffer.

## Config (config.json)

```json
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "185.208.175.228",
  "CONNECT_PORT": 443,
  "ENDPOINTS": [{"ip": "185.208.175.228", "port": 443}],
  "FAKE_SNI": "hcaptcha.com",
  "FAKE_SNIS": ["hcaptcha.com", "cloudflare.com"],
  "BYPASS_METHOD": "wrong_seq",
  "HANDSHAKE_TIMEOUT": 2.0,
  "MAX_CONNECTIONS": 200,
  "FAKE_DELAY": 0.001
}
```

Legacy v1 files (only `CONNECT_IP`/`FAKE_SNI`) still load — they auto-migrate.
GUI extras live in `config.json.full.json`; `xray_config.json` is regenerated on save.

## Layout

- `gui.py` — Tkinter GUI (DPI Bypass / Proxy-Xray / Smart Tools tabs)
- `main.py` — injector + relay (needs Admin)
- `fake_tcp.py`, `injecter.py` — WinDivert logic
- `monitor_connection.py` — stats
- `utils/config_manager.py` — config schema/validation
- `utils/smart.py` — latency/TLS/health probes (stdlib only)
- `utils/network_tools.py`, `utils/packet_templates.py` — unchanged core

## Credits

Original: Patterniha · t.me/patterniha · t.me/projectXhttp
GUI modernization: Xenon using DeepSeek AI · v2 hardening: this upgrade.
