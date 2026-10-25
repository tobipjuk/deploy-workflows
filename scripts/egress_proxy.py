#!/usr/bin/env python3
"""Egress allowlist proxy for the Terraform sandbox (Guardian M2). Stdlib only.

The sandbox user's traffic is dropped by iptables except to this proxy (scripts/tf_sandbox.sh),
and Terraform/providers reach it through HTTPS_PROXY. Only `CONNECT host:443` to allowlisted
hostnames is relayed: AWS endpoints and the Terraform registry/releases (provider downloads at
init). DNS is not available to the sandbox at all; the proxy resolves, and refuses names that
resolve to private, loopback, link-local or otherwise non-global addresses (no IMDS, no runner
services). Hostnames are never logged (a refused name could carry a secret into the job log);
only counts go to the stats file.

  egress_proxy.py --port 3128 --stats FILE
"""
import argparse
import ipaddress
import json
import re
import select
import socket
import socketserver
import sys
import threading

ALLOWED_HOSTS = [
    re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+amazonaws\.com$"),
    re.compile(r"^registry\.terraform\.io$"),
    re.compile(r"^releases\.hashicorp\.com$"),
]
MAX_HEADER = 8192
IDLE_TIMEOUT = 300

_stats = {"allowed": 0, "refused": 0}
_lock = threading.Lock()
_stats_path = None


def host_allowed(host):
    host = host.lower().rstrip(".")
    return len(host) <= 253 and any(p.match(host) for p in ALLOWED_HOSTS)


def global_address(ip):
    a = ipaddress.ip_address(ip)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_global


def parse_connect(head):
    """b'CONNECT host:443 HTTP/1.1\\r\\n...' -> (host, port) or None."""
    try:
        line = head.split(b"\r\n", 1)[0].decode("ascii")
    except UnicodeDecodeError:
        return None
    m = re.fullmatch(r"CONNECT ([A-Za-z0-9.-]+):([0-9]{1,5}) HTTP/1\.[01]", line)
    if not m:
        return None
    return m.group(1), int(m.group(2))


def _count(key):
    with _lock:
        _stats[key] += 1
        if _stats_path:
            with open(_stats_path, "w") as f:
                json.dump(_stats, f)


def _relay(a, b):
    socks = [a, b]
    while True:
        r, _, x = select.select(socks, [], socks, IDLE_TIMEOUT)
        if x or not r:
            return
        for s in r:
            data = s.recv(65536)
            if not data:
                return
            (b if s is a else a).sendall(data)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        c = self.request
        c.settimeout(30)
        head = b""
        try:
            while b"\r\n\r\n" not in head and len(head) < MAX_HEADER:
                chunk = c.recv(1024)
                if not chunk:
                    return
                head += chunk
        except OSError:
            return
        target = parse_connect(head)
        if not target or target[1] != 443 or not host_allowed(target[0]):
            _count("refused")
            c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        host, port = target
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addr = next(i[4] for i in infos if global_address(i[4][0]))
        except (OSError, StopIteration, ValueError):
            _count("refused")
            c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        try:
            up = socket.create_connection(addr[:2], timeout=30)
        except OSError:
            _count("refused")
            c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        _count("allowed")
        c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        rest = head.split(b"\r\n\r\n", 1)[1]
        if rest:
            up.sendall(rest)
        c.settimeout(None)
        up.settimeout(None)
        try:
            _relay(c, up)
        except OSError:
            pass
        finally:
            up.close()


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main(argv=None):
    global _stats_path
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=3128)
    ap.add_argument("--stats")
    args = ap.parse_args(argv)
    _stats_path = args.stats
    if _stats_path:
        with open(_stats_path, "w") as f:
            json.dump(_stats, f)
    with Server(("127.0.0.1", args.port), Handler) as srv:
        print(f"egress proxy on 127.0.0.1:{args.port}", flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
