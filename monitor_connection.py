# monitor_connection.py
import socket
import threading


class MonitorConnection:
    def __init__(self, sock: socket.socket, src_ip, dst_ip,
                 src_port, dst_port):
        self.monitor = True
        self.syn_seq = -1
        self.syn_ack_seq = -1
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.id = (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        self.thread_lock = threading.Lock()
        self.sock = sock


# ========== آمار سراسری برای ارتباط با GUI ==========
_stats_lock = threading.Lock()
_active_connections = 0
_total_connections = 0


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


def get_active():
    with _stats_lock:
        return _active_connections


def get_total():
    with _stats_lock:
        return _total_connections


def reset_stats():
    global _active_connections, _total_connections
    with _stats_lock:
        _active_connections = 0
        _total_connections = 0
