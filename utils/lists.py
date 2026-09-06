# utils/lists.py — loaders for ip_list.txt / sni_list.txt (stdlib only).
from __future__ import annotations

import ipaddress
import os
import random


def load_sni_list(path: str, max_total: int = 200) -> list[str]:
    """Load candidate SNIs, one per line (also tolerates comma/semicolon/space separated).

    Skips blanks and lines starting with '#'. Dedups preserving order.
    Only keeps plausible hostnames (contains '.', no spaces or slashes).
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return []
    # Support both newline-separated (sni_list.txt) and inline lists.
    text = text.replace(",", " ").replace(";", " ")
    seen: set[str] = set()
    out: list[str] = []
    for tok in text.split():
        s = tok.strip().lower()
        if not s or s.startswith("#"):
            continue
        # strip inline trailing comments like "example.com # comment"
        if "#" in s:
            s = s.split("#", 1)[0].strip()
            if not s:
                continue
        if " " in s or "/" in s or "." not in s:
            continue
        if len(s) > 253:
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) >= max_total:
            break
    return out


def _sample_hosts(net: ipaddress._BaseNetwork, per_cidr: int, rng: random.Random) -> list[str]:
    """Sample up to per_cidr usable host IPs from a network.

    Skips network/broadcast for IPv4; skips network addr generally.
    Deterministic-ish: first hosts + random picks, sorted for stability.
    """
    try:
        size = int(net.num_addresses)
    except Exception:
        return []
    if size <= 0:
        return []
    if size == 1:
        return [str(net.network_address)]
    if size == 2:
        # /31: both usable
        return [str(ip) for ip in net][:per_cidr]
    # Normal case: iterate hosts but cap iteration for huge nets (/14 etc.)
    hosts: list[str] = []
    try:
        it = net.hosts()
        # Take first per_cidr hosts directly (cheap, no full expansion)
        for _ in range(per_cidr):
            try:
                hosts.append(str(next(it)))
            except StopIteration:
                break
    except Exception:
        return hosts
    # For larger nets, add a few random offsets for diversity.
    if size > per_cidr * 4:
        try:
            base = int(net.network_address)
            for _ in range(per_cidr):
                off = rng.randint(1, size - 2)
                hosts.append(str(ipaddress.ip_address(base + off)))
        except Exception:
            pass
    # Dedup preserving order, cap
    seen: set[str] = set()
    out: list[str] = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
        if len(out) >= per_cidr * 2:
            break
    return out[: max(1, per_cidr)]


def load_ip_list(path: str, default_port: int = 443, per_cidr: int = 4,
                 max_total: int = 32, seed: int = 7) -> list[dict]:
    """Load candidate endpoints from ip_list.txt.

    Accepts per line (or space/comma separated):
      1.2.3.4  |  1.2.3.4:8443  |  10.0.0.0/24  |  10.0.0.0/24:443
    Skips blanks / '#' comments. CIDRs are sampled (per_cidr hosts each)
    so huge ranges like /14 don't explode. Returns [{ip, port}].
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = f.read().splitlines()
    except OSError:
        return []
    rng = random.Random(seed)
    out: list[dict] = []
    seen: set[tuple] = set()

    def push(ip: str, port: int):
        key = (ip, port)
        if key in seen:
            return
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return
        if not 1 <= port <= 65535:
            return
        seen.add(key)
        out.append({"ip": ip, "port": port})

    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # allow inline comments
        if "#" in line:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
        # a line may hold several tokens
        for tok in line.replace(",", " ").replace(";", " ").split():
            tok = tok.strip()
            if not tok:
                continue
            # split optional :port (only last colon; CIDR has no colon)
            port = default_port
            addr = tok
            if "/" in tok:
                # CIDR with optional :port suffix, e.g. 10.0.0.0/24:443
                base, _, suffix = tok.rpartition(":")
                if suffix.isdigit() and "/" in base:
                    try:
                        p = int(suffix)
                        if 1 <= p <= 65535:
                            port = p
                            addr = base
                    except ValueError:
                        pass
                try:
                    net = ipaddress.ip_network(addr, strict=False)
                except ValueError:
                    continue
                if not isinstance(net, ipaddress.IPv4Network):
                    continue
                for h in _sample_hosts(net, per_cidr, rng):
                    push(h, port)
                    if len(out) >= max_total:
                        return out
            else:
                if ":" in tok:
                    ip_part, _, port_s = tok.rpartition(":")
                    try:
                        port = int(port_s)
                    except ValueError:
                        continue
                    addr = ip_part.strip()
                try:
                    ipaddress.IPv4Address(addr)
                except ValueError:
                    continue
                push(addr, port)
                if len(out) >= max_total:
                    return out
    return out


def default_list_paths(app_dir: str) -> tuple[str, str]:
    return (os.path.join(app_dir, "ip_list.txt"),
            os.path.join(app_dir, "sni_list.txt"))
