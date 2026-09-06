# monitor_connection.py — connection tracking + global stats (thread-safe).
from __future__ import annotations

import socket
import threading
import time


class MonitorConnection:
    def __init__(self, sock: socket.socket, src_ip, dst_ip, src_port, dst_port):
        self.monitor = True
        self.syn_seq = -1
        self.syn_ack_seq = -1
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.id = (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        # RLock: fake_send_thread (split_seq) checks monitor mid-send while
        # already holding the lock; a plain Lock would deadlock there.
        self.thread_lock = threading.RLock()
        self.sock = sock
        self.created_at = time.time()


_stats_lock = threading.Lock()
_active_connections = 0
_total_connections = 0
_success_connections = 0
_failed_connections = 0
# Traffic totals: up = clients -> internet, down = internet -> clients.
_up_bytes = 0
_down_bytes = 0
_start_time = time.time()
# scoreboard: "ip:port" -> {"ok": n, "fail": n}; sni board: sni -> {...}
_method_board: dict[str, dict[str, int]] = {}
_endpoint_board: dict[str, dict[str, int]] = {}
_sni_board: dict[str, dict[str, int]] = {}


def increment_active():
    global _active_connections
    with _stats_lock:
        _active_connections += 1


def decrement_active():
    global _active_connections
    with _stats_lock:
        if _active_connections > 0:
            _active_connections -= 1


def increment_total():
    global _total_connections
    with _stats_lock:
        _total_connections += 1


def increment_success():
    global _success_connections
    with _stats_lock:
        _success_connections += 1


def increment_failed():
    global _failed_connections
    with _stats_lock:
        _failed_connections += 1


def add_traffic(up: int = 0, down: int = 0):
    """Add relayed bytes. Thread-safe, never raises."""
    global _up_bytes, _down_bytes
    try:
        with _stats_lock:
            _up_bytes += max(0, int(up))
            _down_bytes += max(0, int(down))
    except Exception:
        pass


def get_traffic() -> tuple:
    with _stats_lock:
        return _up_bytes, _down_bytes


def finish_success():
    """Handshake bypass succeeded: no longer monitored, no longer 'active'."""
    decrement_active()
    increment_success()


def finish_failed():
    """Handshake bypass failed."""
    decrement_active()
    increment_failed()


def get_active():
    with _stats_lock:
        return _active_connections


def get_total():
    with _stats_lock:
        return _total_connections


def get_success():
    with _stats_lock:
        return _success_connections


def get_failed():
    with _stats_lock:
        return _failed_connections


def record_result(endpoint: str = "", sni: str = "", ok: bool = True, method: str = ""):
    """Learn per-endpoint / per-SNI / per-method bypass success. Thread-safe, never raises."""
    try:
        with _stats_lock:
            if endpoint:
                cell = _endpoint_board.setdefault(endpoint, {"ok": 0, "fail": 0})
                cell["ok" if ok else "fail"] += 1
            if sni:
                cell = _sni_board.setdefault(sni, {"ok": 0, "fail": 0})
                cell["ok" if ok else "fail"] += 1
            if method:
                cell = _method_board.setdefault(str(method), {"ok": 0, "fail": 0})
                cell["ok" if ok else "fail"] += 1
    except Exception:
        pass


def _rate(cell: dict) -> float:
    tot = cell.get("ok", 0) + cell.get("fail", 0)
    return (cell.get("ok", 0) / tot) if tot else 0.0


def _ranked(board: dict, limit: int) -> list:
    return sorted(
        ({"key": k, "ok": v["ok"], "fail": v["fail"], "rate": round(_rate(v), 3)}
         for k, v in board.items()),
        key=lambda r: (-r["rate"], -(r["ok"] + r["fail"]), r["key"]),
    )[: max(0, limit)]


def get_scoreboard(limit: int = 5) -> dict:
    """Top endpoints/SNIs/methods by success rate. Safe copy, no lock held on return."""
    with _stats_lock:
        eps = _ranked(_endpoint_board, limit)
        snis = _ranked(_sni_board, limit)
        methods = _ranked(_method_board, limit)
        tot_ok = _success_connections
        tot_fail = _failed_connections
        tot = tot_ok + tot_fail
        return {
            "endpoints": eps,
            "snis": snis,
            "methods": methods,
            "best_endpoint": eps[0]["key"] if eps else "",
            "best_sni": snis[0]["key"] if snis else "",
            "best_method": methods[0]["key"] if methods else "",
            "success_rate": round(tot_ok / tot, 3) if tot else 0.0,
        }


def get_snapshot() -> dict:
    with _stats_lock:
        tot = _success_connections + _failed_connections
        eps = _ranked(_endpoint_board, 5)
        methods = _ranked(_method_board, 3)
        return {
            "type": "stats",
            "active": _active_connections,
            "total": _total_connections,
            "success": _success_connections,
            "failed": _failed_connections,
            "uptime": round(time.time() - _start_time, 1),
            "success_rate": round(_success_connections / tot, 3) if tot else 0.0,
            "best_endpoint": eps[0]["key"] if eps else "",
            "best_method": methods[0]["key"] if methods else "",
            "methods": methods,
            "up_bytes": _up_bytes,
            "down_bytes": _down_bytes,
            "scoreboard": {
                "endpoints": eps,
            },
        }


def reset_stats():
    global _active_connections, _total_connections, _success_connections, _failed_connections, _start_time
    global _up_bytes, _down_bytes
    with _stats_lock:
        _active_connections = 0
        _total_connections = 0
        _success_connections = 0
        _failed_connections = 0
        _up_bytes = 0
        _down_bytes = 0
        _start_time = time.time()
        _endpoint_board.clear()
        _sni_board.clear()
        _method_board.clear()
