#!/usr/bin/env python3
"""port-scout: a small multithreaded TCP connect port scanner.

For learning and authorized testing only. Only scan hosts you own
or have explicit permission to scan.
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

# ports worth checking when you don't want to scan a whole range
COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 27017,
]

# best-guess service names for well-known ports, nothing fancy
SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}


def parse_ports(spec):
    """Turn '80', '20-25', or '22,80,443' into a sorted list of ints."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, _, end = part.partition("-")
            try:
                start, end = int(start), int(end)
            except ValueError:
                raise ValueError(f"bad port range: {part!r}")
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"port range out of bounds: {part!r}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"bad port: {part!r}")
            if not 1 <= port <= 65535:
                raise ValueError(f"port out of bounds: {part!r}")
            ports.add(port)
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def grab_banner(ip, port, timeout):
    """Connect and try to read a banner. Returns (is_open, banner)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            # some services only talk after you send something; we just
            # listen briefly, which is enough for ssh/ftp/smtp-style banners
            sock.settimeout(min(timeout, 2.0))
            try:
                data = sock.recv(1024)
            except (socket.timeout, ConnectionResetError, OSError):
                data = b""
            banner = data.decode("utf-8", errors="replace").strip().split("\n")[0]
            return True, banner[:80]
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, ""


def scan(ip, ports, threads, timeout):
    results = {}  # port -> (is_open, banner)

    def worker(port):
        results[port] = grab_banner(ip, port, timeout)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        list(pool.map(worker, ports))
    return results


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"error: can't resolve {target!r}", file=sys.stderr)
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(
        description="port-scout: multithreaded TCP connect port scanner "
                    "(for hosts you own or may test)"
    )
    parser.add_argument("target", help="hostname or IP to scan")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ports", help="ports to scan: '80', '20-25', '22,80,443'")
    group.add_argument("--common", action="store_true",
                       help="scan a preset list of common ports")
    parser.add_argument("--threads", type=int, default=100,
                        help="worker threads (default 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="connect timeout in seconds (default 1.0)")
    args = parser.parse_args()

    if args.threads < 1 or args.threads > 1000:
        parser.error("threads must be between 1 and 1000")
    if args.timeout <= 0 or args.timeout > 30:
        parser.error("timeout must be between 0 and 30 seconds")

    ip = resolve_target(args.target)
    ports = COMMON_PORTS if args.common else parse_ports(args.ports)

    print(f"scanning {args.target} ({ip}) — {len(ports)} ports, "
          f"{args.threads} threads")
    start = time.time()
    try:
        results = scan(ip, ports, args.threads, args.timeout)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(1)
    elapsed = time.time() - start

    open_ports = [p for p, (is_open, _) in results.items() if is_open]
    print(f"\n{'PORT':<8}{'STATE':<9}{'SERVICE':<12}BANNER")
    for port in sorted(results):
        is_open, banner = results[port]
        state = "open" if is_open else "closed"
        service = SERVICE_NAMES.get(port, "-")
        print(f"{port:<8}{state:<9}{service:<12}{banner}")
    print(f"\ndone: {len(ports)} ports in {elapsed:.2f}s — "
          f"{len(open_ports)} open")


if __name__ == "__main__":
    main()
