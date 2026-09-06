# main.py — SNI spoofing relay + WinDivert injector (v2, hardened).
from __future__ import annotations

import argparse
import asyncio
import itertools
import json
import logging
import os
import signal
import socket
import sys
import threading
import traceback

from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector, SUPPORTED_METHODS, REAL_METHODS
from monitor_connection import reset_stats, get_snapshot, increment_failed, finish_failed, record_result
from monitor_connection import add_traffic

log = logging.getLogger("main")


def get_exe_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def parse_args():
    p = argparse.ArgumentParser(description="SNI Spoofing injector")
    p.add_argument("--config", dest="config", default=None,
                   help="Path to config.json (default: next to script/exe)")
    p.add_argument("--log-level", default=os.environ.get("SNI_LOG", "INFO"),
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--self-test", action="store_true",
                   help="Run offline self-test (no Admin/WinDivert needed) and exit")
    return p.parse_known_args()[0]


def run_self_test(config_path: str) -> int:
    """Offline checks: config, packet template, scoreboard, split math. Returns exit code."""
    results: dict = {"checks": {}}
    ok_all = True

    def check(name: str, fn):
        nonlocal ok_all
        try:
            detail = fn()
            results["checks"][name] = {"ok": True, "detail": detail}
        except Exception as exc:
            ok_all = False
            results["checks"][name] = {"ok": False, "detail": str(exc)[:300]}

    def _cfg():
        cfg = load_config(config_path)
        return f"{len(cfg['ENDPOINTS'])} endpoint(s), {len(cfg['FAKE_SNIS'])} SNI(s), method={cfg['BYPASS_METHOD']}"

    def _template():
        rnd, sess, key = os.urandom(32), os.urandom(32), os.urandom(32)
        hello = ClientHelloMaker.get_client_hello_with(rnd, sess, b"example.com", key)
        r2, s2, sni2, k2 = ClientHelloMaker.parse_client_hello(hello)
        assert sni2 == "example.com" and r2 == rnd and s2 == sess and k2 == key
        assert len(hello) == 517
        return f"ClientHello {len(hello)}B round-trip OK"

    def _score():
        reset_stats()
        record_result("1.1.1.1:443", "a.com", True)
        record_result("1.1.1.1:443", "a.com", False)
        snap = get_snapshot()
        assert snap["success_rate"] == 0.0  # counters untouched by record_result
        from monitor_connection import get_scoreboard
        board = get_scoreboard()
        assert board["endpoints"] and board["endpoints"][0]["key"] == "1.1.1.1:443"
        reset_stats()
        return "scoreboard OK"

    def _split():
        from fake_tcp import split_plan
        s1, s2 = split_plan(1000, 517, 258)
        assert s2 == (s1 + 258) & 0xFFFFFFFF
        assert s1 == (1001 - 517) & 0xFFFFFFFF
        return "split math OK"

    def _smart():
        from utils import smart, config_manager
        from fake_tcp import resolve_method
        assert isinstance(smart.SUGGESTED_SNIS, list) and len(smart.SUGGESTED_SNIS) > 3
        assert config_manager.validate(config_manager.migrate({})) == []
        bad = {"CONNECT_IP": "", "CONNECT_PORT": 443, "ENDPOINTS": [],
               "FAKE_SNI": "", "FAKE_SNIS": []}
        assert config_manager.validate(config_manager.migrate(bad)) != []
        assert config_manager.validate(config_manager.migrate({"BYPASS_METHOD": "auto"})) == []
        assert resolve_method("auto") in REAL_METHODS
        assert resolve_method("split_seq") == "split_seq"
        # split_seq re-checks monitor mid-send while holding the per-conn
        # lock (fake_tcp) — the lock must be re-entrant or split deadlocks.
        import socket as _sock
        from monitor_connection import MonitorConnection
        _mc = MonitorConnection(_sock.socket(), "127.0.0.1", "127.0.0.1", 1, 443)
        try:
            acquired = _mc.thread_lock.acquire(blocking=False)
            assert acquired, "conn lock unavailable"
            assert _mc.thread_lock.acquire(blocking=False), "conn lock not re-entrant (split_seq would deadlock)"
            _mc.thread_lock.release()
            _mc.thread_lock.release()
        finally:
            try:
                _mc.sock.close()
            except Exception:
                pass
        assert smart.rank_snis("127.0.0.1", 9, []) == []
        return "helpers OK"

    check("config", _cfg)
    check("packet_template", _template)
    check("scoreboard", _score)
    check("split_plan", _split)
    check("helpers", _smart)
    results["ok"] = ok_all
    print(json.dumps(results, indent=2), flush=True)
    return 0 if ok_all else 1


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    # --- v1 -> v2 migration -------------------------------------------------
    # v1: {LISTEN_HOST, LISTEN_PORT, CONNECT_IP, CONNECT_PORT, FAKE_SNI}
    # v2 adds: ENDPOINTS[], FAKE_SNIS[], BYPASS_METHOD, HANDSHAKE_TIMEOUT, ...
    endpoints = []
    if isinstance(cfg.get("ENDPOINTS"), list) and cfg["ENDPOINTS"]:
        for e in cfg["ENDPOINTS"]:
            if isinstance(e, dict) and e.get("ip"):
                endpoints.append({"ip": str(e["ip"]).strip(),
                                  "port": int(e.get("port", cfg.get("CONNECT_PORT", 443)))})
            elif isinstance(e, str):
                endpoints.append({"ip": e.strip(), "port": int(cfg.get("CONNECT_PORT", 443))})
    elif cfg.get("CONNECT_IP"):
        endpoints.append({"ip": str(cfg["CONNECT_IP"]).strip(),
                          "port": int(cfg.get("CONNECT_PORT", 443))})
    if not endpoints:
        raise ValueError("No endpoints configured (CONNECT_IP or ENDPOINTS required)")

    fake_snis: list[str] = []
    if isinstance(cfg.get("FAKE_SNIS"), list) and cfg["FAKE_SNIS"]:
        fake_snis = [str(s).strip() for s in cfg["FAKE_SNIS"] if str(s).strip()]
    elif cfg.get("FAKE_SNI"):
        fake_snis = [str(cfg["FAKE_SNI"]).strip()]
    if not fake_snis:
        raise ValueError("No FAKE_SNI configured")

    method = str(cfg.get("BYPASS_METHOD", "auto")).strip() or "auto"
    if method not in SUPPORTED_METHODS:
        raise ValueError(f"Unsupported BYPASS_METHOD={method!r} (expected one of {SUPPORTED_METHODS})")

    out = {
        "LISTEN_HOST": str(cfg.get("LISTEN_HOST", "0.0.0.0")),
        "LISTEN_PORT": int(cfg.get("LISTEN_PORT", 40443)),
        "ENDPOINTS": endpoints,
        "FAKE_SNIS": fake_snis,
        "BYPASS_METHOD": method,
        "HANDSHAKE_TIMEOUT": float(cfg.get("HANDSHAKE_TIMEOUT", 2.0)),
        "MAX_CONNECTIONS": int(cfg.get("MAX_CONNECTIONS", 200)),
        "FAKE_DELAY": float(cfg.get("FAKE_DELAY", 0.001)),
        "DATA_MODE": "tls",
    }
    return out


args = parse_args()
logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")


class _OverlappedCancelFilter(logging.Filter):
    """Drop Windows asyncio noise: 'Cancelling an overlapped future failed'
    with WinError 6. Happens when relay sockets close while a sock_recv /
    sock_accept is still pending — harmless, but spams the GUI console."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage().lower()
        except Exception:
            return True
        if "cancelling an overlapped future failed" in msg:
            return False
        if "overlappedfuture" in msg and ("winerror 6" in msg or "handle is invalid" in msg):
            return False
        return True


try:
    logging.getLogger("asyncio").addFilter(_OverlappedCancelFilter())
except Exception:
    pass
config_path = os.path.abspath(args.config) if args.config else os.path.join(get_exe_dir(), "config.json")
if args.self_test:
    sys.exit(run_self_test(config_path))
try:
    config = load_config(config_path)
except Exception as exc:
    print(f"FATAL: cannot load config {config_path}: {exc}", flush=True)
    sys.exit(2)

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
ENDPOINTS: list[dict] = config["ENDPOINTS"]
FAKE_SNIS: list[str] = config["FAKE_SNIS"]
BYPASS_METHOD = config["BYPASS_METHOD"]
HANDSHAKE_TIMEOUT = config["HANDSHAKE_TIMEOUT"]
MAX_CONNECTIONS = config["MAX_CONNECTIONS"]
FAKE_DELAY = config["FAKE_DELAY"]
DATA_MODE = "tls"

# Round-robin endpoint picker with failover in handle().
_endpoint_cycle = itertools.cycle(range(len(ENDPOINTS)))
_cycle_lock = threading.Lock()


def pick_endpoints() -> list[dict]:
    """Return endpoints ordered for this connection (round-robin start, then rest)."""
    with _cycle_lock:
        start = next(_endpoint_cycle)
    return [ENDPOINTS[(start + i) % len(ENDPOINTS)] for i in range(len(ENDPOINTS))]


def pick_sni() -> str:
    # Rotate SNIs to spread fingerprint; random choice per connection.
    import random
    return random.choice(FAKE_SNIS)


def ep_key(ep: dict) -> str:
    return f"{ep['ip']}:{ep['port']}"


def note_fail(conn, endpoint: str, sni: str):
    """Record a failed attempt without double-counting injector stats.

    If the injector already counted this connection (finish_failed via
    on_unexpected_packet), only the scoreboard needs updating. Otherwise
    the engine owns the failure counter.
    """
    try:
        method = getattr(conn, "bypass_method", "") or ""
    except Exception:
        method = ""
    record_result(endpoint, sni, False, method=method)
    try:
        if conn is not None and getattr(conn, "counted", False):
            conn.monitor = False
            finish_failed()
            conn.counted = False
        else:
            increment_failed()
    except Exception:
        pass


INTERFACE_IPV4 = get_default_interface_ipv4(ENDPOINTS[0]["ip"])
if not INTERFACE_IPV4:
    print("FATAL: cannot determine default interface IPv4 (no route?)", flush=True)
    sys.exit(2)

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}
shutdown_event = threading.Event()
conn_sem = threading.BoundedSemaphore(MAX_CONNECTIONS)


def set_keepalive(sock: socket.socket):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for level, opt, val in (
        (socket.IPPROTO_TCP, getattr(socket, "TCP_KEEPIDLE", None), 11),
        (socket.IPPROTO_TCP, getattr(socket, "TCP_KEEPINTVL", None), 2),
        (socket.IPPROTO_TCP, getattr(socket, "TCP_KEEPCNT", None), 3),
    ):
        if opt is None:
            continue
        try:
            sock.setsockopt(level, opt, val)
        except OSError:
            pass


async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task,
                           first_prefix_data: bytes, direction: str = ""):
    """Forward sock_1 -> sock_2. direction 'up' (clients->net) / 'down' feeds the traffic tracker."""
    loop = asyncio.get_running_loop()
    try:
        while True:
            try:
                data = await loop.sock_recv(sock_1, 65575)
                if not data:
                    raise ConnectionError("eof")
                if first_prefix_data:
                    data = first_prefix_data + data
                    first_prefix_data = b""
                if direction == "up":
                    add_traffic(up=len(data))
                elif direction == "down":
                    add_traffic(down=len(data))
                await loop.sock_sendall(sock_2, data)
            except (ConnectionError, OSError):
                break
            except asyncio.CancelledError:
                break
            except Exception:
                log.debug("relay error", exc_info=True)
                break
    finally:
        for s in (sock_1, sock_2):
            try:
                s.close()
            except Exception:
                pass
        if peer_task and not peer_task.done():
            peer_task.cancel()


async def try_connect(loop: asyncio.AbstractEventLoop, sock: socket.socket,
                     ordered: list[dict]) -> dict | None:
    """Try endpoints in order; return the one that connected, else None."""
    last_err: Exception | None = None
    for ep in ordered:
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (ep["ip"], ep["port"])), timeout=5)
            return ep
        except Exception as exc:
            last_err = exc
            continue
    log.debug("all endpoints failed: %s", last_err)
    return None


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    loop = asyncio.get_running_loop()
    if not conn_sem.acquire(blocking=False):
        log.warning("connection limit reached, dropping %s", incoming_remote_addr)
        try:
            incoming_sock.close()
        except Exception:
            pass
        increment_failed()
        return
    outgoing_sock: socket.socket | None = None
    conn: FakeInjectiveConnection | None = None
    sni_str = ""
    cur_ep_key = ""
    try:
        sni_str = pick_sni()
        fake_sni = sni_str.encode()
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), fake_sni, os.urandom(32))
        else:
            log.error("impossible DATA_MODE=%s", DATA_MODE)
            incoming_sock.close()
            return

        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        try:
            outgoing_sock.bind((INTERFACE_IPV4, 0))
        except OSError as exc:
            log.error("bind failed: %s", exc)
            incoming_sock.close()
            outgoing_sock.close()
            return
        set_keepalive(outgoing_sock)
        try:
            src_port = outgoing_sock.getsockname()[1]
        except OSError:
            incoming_sock.close()
            outgoing_sock.close()
            return

        ordered = pick_endpoints()
        # Pre-register with the FIRST endpoint; on failover we re-key below.
        first = ordered[0]
        conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, first["ip"], src_port, first["port"],
                                       fake_data, BYPASS_METHOD, incoming_sock)
        fake_injective_connections[conn.id] = conn

        connected_ep = await try_connect(loop, outgoing_sock, ordered)
        if connected_ep is None:
            conn.monitor = False
            fake_injective_connections.pop(conn.id, None)
            note_fail(None, ep_key(first), sni_str)
            outgoing_sock.close()
            incoming_sock.close()
            return
        cur_ep_key = ep_key(connected_ep)
        if connected_ep is not first:
            # Re-key dict to the real endpoint so WinDivert filter matches.
            fake_injective_connections.pop(conn.id, None)
            conn.dst_ip = connected_ep["ip"]
            conn.dst_port = connected_ep["port"]
            conn.id = (conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port)
            fake_injective_connections[conn.id] = conn

        if BYPASS_METHOD in SUPPORTED_METHODS:
            try:
                await asyncio.wait_for(conn.t2a_event.wait(), HANDSHAKE_TIMEOUT)
                if conn.t2a_msg != "fake_data_ack_recv":
                    raise ConnectionError(f"bypass failed: {conn.t2a_msg or 'timeout'}")
            except Exception:
                conn.monitor = False
                fake_injective_connections.pop(conn.id, None)
                # Injector already recorded stats via finish_failed() when it
                # saw the unexpected packet; note_fail() avoids double count.
                note_fail(conn, cur_ep_key or ep_key(first), sni_str)
                try:
                    outgoing_sock.close()
                except Exception:
                    pass
                try:
                    incoming_sock.close()
                except Exception:
                    pass
                return
            else:
                record_result(cur_ep_key or ep_key(first), sni_str, True,
                              method=getattr(conn, "bypass_method", "") or "")
        else:
            log.error("unknown bypass method: %s", BYPASS_METHOD)
            conn.monitor = False
            fake_injective_connections.pop(conn.id, None)
            note_fail(conn, cur_ep_key or ep_key(first), sni_str)
            outgoing_sock.close()
            incoming_sock.close()
            return

        conn.monitor = False
        fake_injective_connections.pop(conn.id, None)

        oti_task = asyncio.create_task(relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b"", "down"))
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"", "up")
    except Exception:
        log.error("handle error", exc_info=True)
        try:
            incoming_sock.close()
        except Exception:
            pass
        if outgoing_sock is not None:
            try:
                outgoing_sock.close()
            except Exception:
                pass
        if conn is not None:
            try:
                if conn.monitor:
                    note_fail(conn, cur_ep_key, sni_str)
                conn.monitor = False
                fake_injective_connections.pop(conn.id, None)
            except Exception:
                pass
    finally:
        try:
            conn_sem.release()
        except ValueError:
            pass


async def stats_reporter(interval: float = 2.0):
    while True:
        try:
            print(json.dumps(get_snapshot()), flush=True)
        except Exception:
            pass
        await asyncio.sleep(interval)


async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    except OSError as exc:
        print(f"FATAL: cannot bind {LISTEN_HOST}:{LISTEN_PORT}: {exc}", flush=True)
        sys.exit(2)
    set_keepalive(mother_sock)
    mother_sock.listen(256)
    loop = asyncio.get_running_loop()

    print(f"Server started on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    print(f"Fake SNIs: {', '.join(FAKE_SNIS)}", flush=True)
    print(f"Endpoints: {', '.join(e['ip'] + ':' + str(e['port']) for e in ENDPOINTS)}", flush=True)
    print(f"Bypass method: {BYPASS_METHOD} (timeout={HANDSHAKE_TIMEOUT}s, max_conn={MAX_CONNECTIONS})", flush=True)
    if BYPASS_METHOD == "auto":
        print(f"Auto-rotate pool: {', '.join(REAL_METHODS)}", flush=True)

    asyncio.create_task(stats_reporter())

    while not shutdown_event.is_set():
        try:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            if shutdown_event.is_set():
                break
            log.warning("accept failed: %s", exc)
            await asyncio.sleep(0.05)
            continue
        incoming_sock.setblocking(False)
        set_keepalive(incoming_sock)
        asyncio.create_task(handle(incoming_sock, addr))

    try:
        mother_sock.close()
    except Exception:
        pass


if __name__ == "__main__":
    def signal_handler(sig, frame):
        print("\nShutting down...", flush=True)
        shutdown_event.set()

    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    except Exception:
        pass

    reset_stats()

    filt = "tcp and (" + " or ".join(
        f"(ip.SrcAddr == {INTERFACE_IPV4} and ip.DstAddr == {e['ip']})"
        f" or (ip.SrcAddr == {e['ip']} and ip.DstAddr == {INTERFACE_IPV4})"
        for e in ENDPOINTS) + ")"
    injector = FakeTcpInjector(filt, fake_injective_connections, fake_delay=FAKE_DELAY)
    # Pre-flight WinDivert open: fail fast with a clear message instead of
    # starting the relay with a dead injector thread (silent bypass failure).
    try:
        injector.w.open()
    except PermissionError:
        print("FATAL: WinDivert open failed: Access is denied. Run as Administrator.", flush=True)
        sys.exit(2)
    except OSError as exc:
        print(f"FATAL: WinDivert open failed: {exc}", flush=True)
        sys.exit(2)
    except Exception as exc:
        print(f"FATAL: WinDivert open failed: {exc}", flush=True)
        sys.exit(2)
    try:
        injector.w.close()
    except Exception:
        pass
    injector_thread = threading.Thread(target=injector.run, daemon=True)
    injector_thread.start()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        sys.exit(1)
    finally:
        shutdown_event.set()
        try:
            injector.stop()
        except Exception:
            pass
