#!/usr/bin/env python3
"""Egress allowlist proxy for the Terraform sandbox (Guardian M2). Stdlib only.

The sandbox user's traffic is dropped by iptables except to this proxy (scripts/tf_sandbox.sh),
and Terraform/providers reach it through HTTPS_PROXY. Only `CONNECT host:443` to an EXACT host
list is relayed: the project's AWS endpoints and buckets (scripts/egress_hosts.py, one host per
line in --hosts-file) plus the Terraform registry/releases hosts (provider downloads at init).
No wildcards: `*.amazonaws.com` includes attacker-ownable hosts (S3 buckets, execute-api, elb). DNS is not available to the sandbox at all; the proxy resolves, and refuses names that
resolve to private, loopback, link-local or otherwise non-global addresses (no IMDS, no runner
services). Hostnames are never logged (a refused name could carry a secret into the job log);
only counts go to the stats file.

  egress_proxy.py --port 3128 --hosts-file FILE --stats FILE --ready-file FILE

--ready-file is written (with this process's pid) only after the listening socket is bound, so
the caller can tell its own proxy from anything else on the port.
"""
import argparse
import ipaddress
import json
import os
import re
import select
import socket
import socketserver
import sys
import threading

FIXED_HOSTS = frozenset({"registry.terraform.io", "releases.hashicorp.com"})
HOST_LINE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_allowed = set(FIXED_HOSTS)
MAX_HEADER = 8192
IDLE_TIMEOUT = 300

_stats = {"allowed": 0, "refused": 0}
_lock = threading.Lock()
_stats_path = None
_debug_path = None  # LOCAL DEBUG ONLY: hostnames go to this private file, never to logs


def load_hosts(path):
    hosts = set()
    with open(path, encoding="ascii") as f:
        for line in f:
            h = line.strip().lower()
            if not h or h.startswith("#"):
                continue
            if not HOST_LINE.match(h) or len(h) > 253:
                raise ValueError(f"bad host line {h!r}")
            hosts.add(h)
    if not hosts:
        raise ValueError("empty host list")
    return hosts


def host_allowed(host, allowed=None):
    host = host.lower().rstrip(".")
    return host in (_allowed if allowed is None else allowed)


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


def _count(key, host=None):
    with _lock:
        _stats[key] += 1
        if _debug_path and host is not None:
            fd = os.open(_debug_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(f"{key.upper()} {host}\n")
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
            _count("refused", target[0] if target else "(not a CONNECT)")
            c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        host, port = target
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addr = next(i[4] for i in infos if global_address(i[4][0]))
        except (OSError, StopIteration, ValueError):
            _count("refused", host + " (no global address)")
            c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        try:
            up = socket.create_connection(addr[:2], timeout=30)
        except OSError:
            _count("refused", host + " (connect failed)")
            c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        _count("allowed", host)
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
    global _stats_path, _allowed, _debug_path
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=3128)
    ap.add_argument("--hosts-file", required=True)
    ap.add_argument("--stats")
    ap.add_argument("--ready-file")
    ap.add_argument("--debug-hosts-file", help="LOCAL DEBUG ONLY: append ALLOWED/REFUSED <host> lines (0600)")
    args = ap.parse_args(argv)
    try:
        _allowed = load_hosts(args.hosts_file) | FIXED_HOSTS
    except (OSError, ValueError) as e:
        print(f"egress proxy: {e}", file=sys.stderr)
        return 1
    _stats_path = args.stats
    if args.debug_hosts_file:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print("egress proxy: --debug-hosts-file is for local debugging only", file=sys.stderr)
            return 1
        _debug_path = args.debug_hosts_file
    if _stats_path:
        with open(_stats_path, "w") as f:
            json.dump(_stats, f)
    try:
        srv = Server(("127.0.0.1", args.port), Handler)
    except OSError as e:
        print(f"egress proxy: cannot bind 127.0.0.1:{args.port}: {e.strerror}", file=sys.stderr)
        return 1
    with srv:
        if args.ready_file:
            with open(args.ready_file, "w") as f:
                f.write(f"{os.getpid()}\n")
        print(f"egress proxy on 127.0.0.1:{args.port}, {len(_allowed)} hosts", flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
