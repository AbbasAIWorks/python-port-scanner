#!/usr/bin/env python3
"""
tcp_udp_scanner.py - A beginner-friendly TCP/UDP port scanner.

FOR EDUCATIONAL USE AND AUTHORIZED TESTING ONLY.
Only scan localhost, lab machines, or systems you own or have written
permission to test. Unauthorized scanning may be illegal.

Requires Python 3.9+ and uses only the standard library.
"""

import argparse
import errno
import ipaddress
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
MIN_PORT, MAX_PORT = 1, 65535
DEFAULT_TIMEOUT = 1.0      # seconds to wait per port (conservative)
DEFAULT_WORKERS = 50       # threads running at the same time
MAX_WORKERS = 500          # hard cap so we never overload the machine

# A short list of commonly used ports (used by --common and as the default).
COMMON_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 137, 139, 143, 161, 389,
    443, 445, 465, 514, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080,
]

# Service "guesses" based ONLY on the port number. These are not proof!
TCP_SERVICES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    8080: "http-alt",
}
UDP_SERVICES: Dict[int, str] = {
    53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
    111: "rpcbind", 123: "ntp", 137: "netbios-ns", 138: "netbios-dgm",
    161: "snmp", 389: "ldap", 500: "isakmp", 514: "syslog", 1900: "ssdp",
    5353: "mdns",
}

# Status labels
OPEN = "OPEN"
CLOSED = "CLOSED"
FILTERED = "FILTERED"
OPEN_FILTERED = "OPEN|FILTERED"
UNKNOWN = "UNKNOWN"

# Error numbers that usually mean "a firewall or router blocked this".
# Windows uses WSA codes (10013, 10051, 10065) instead of errno names.
_FILTER_ERRNOS: Set[int] = {10013, 10051, 10065}
for _name in ("EHOSTUNREACH", "ENETUNREACH", "EACCES", "EPERM"):
    if hasattr(errno, _name):
        _FILTER_ERRNOS.add(getattr(errno, _name))


# ---------------------------------------------------------------------------
# Data structure for one scan result
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    protocol: str                 # "tcp" or "udp"
    port: int
    status: str                   # one of the labels above
    service: str                  # service GUESS from the port number
    rtt_ms: Optional[float]       # response time in ms (None if not measurable)
    note: str = ""                # short explanation


# ---------------------------------------------------------------------------
# Helper functions: services and argument parsing
# ---------------------------------------------------------------------------

def guess_service(protocol: str, port: int) -> str:
    """Guess the service name from the port number (NOT a guarantee)."""
    table = TCP_SERVICES if protocol == "tcp" else UDP_SERVICES
    if port in table:
        return table[port]
    try:
        # Fall back to the operating system's services database.
        return socket.getservbyport(port, protocol)
    except (OSError, OverflowError):
        return "unknown"


def parse_ports(text: str) -> List[int]:
    """Turn '22,80,100-200' into a sorted list of unique port numbers."""
    ports: Set[int] = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            raise ValueError("empty entry in port list (check for extra commas)")
        if "-" in part:
            left, _, right = part.partition("-")
            try:
                start, end = int(left), int(right)
            except ValueError:
                raise ValueError(f"invalid port range '{part}'") from None
            if start > end:
                raise ValueError(f"range '{part}' starts higher than it ends")
            candidates = range(start, end + 1)
            check = (start, end)
        else:
            try:
                single = int(part)
            except ValueError:
                raise ValueError(f"invalid port '{part}'") from None
            candidates = range(single, single + 1)
            check = (single, single)
        if check[0] < MIN_PORT or check[1] > MAX_PORT:
            raise ValueError(f"'{part}' is outside {MIN_PORT}-{MAX_PORT}")
        ports.update(candidates)
    return sorted(ports)


def ports_argument(text: str) -> List[int]:
    """argparse wrapper that converts ValueError into a friendly error."""
    try:
        return parse_ports(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def positive_float(text: str) -> float:
    """argparse type: a number greater than 0 and at most 60."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{text}' is not a number") from None
    if not 0 < value <= 60:
        raise argparse.ArgumentTypeError("timeout must be > 0 and <= 60 seconds")
    return value


def non_negative_float(text: str) -> float:
    """argparse type: a number between 0 and 60."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{text}' is not a number") from None
    if not 0 <= value <= 60:
        raise argparse.ArgumentTypeError("delay must be between 0 and 60 seconds")
    return value


def workers_argument(text: str) -> int:
    """argparse type: thread count between 1 and MAX_WORKERS."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{text}' is not a whole number") from None
    if not 1 <= value <= MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"workers must be 1-{MAX_WORKERS}")
    return value


def resolve_target(target: str) -> str:
    """Convert a hostname or IP string into an IPv4 address string."""
    try:
        # getaddrinfo handles both names and IP literals.
        info = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve '{target}': {exc.strerror or exc}") from None
    except UnicodeError:
        raise ValueError(f"'{target}' is not a valid hostname") from None
    return info[0][4][0]


# ---------------------------------------------------------------------------
# TCP scanning (connect scan - no admin rights needed)
# ---------------------------------------------------------------------------

def scan_tcp(ip: str, port: int, timeout: float) -> ScanResult:
    """Try a full TCP connection and classify the outcome."""
    service = guess_service("tcp", port)
    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((ip, port))
        rtt = (time.perf_counter() - start) * 1000
        return ScanResult("tcp", port, OPEN, service, rtt, "connection accepted")
    except ConnectionRefusedError:
        # The host actively replied with a reset (RST): nothing is listening.
        rtt = (time.perf_counter() - start) * 1000
        return ScanResult("tcp", port, CLOSED, service, rtt, "connection refused")
    except socket.timeout:
        # No answer at all: usually a firewall silently dropping packets.
        return ScanResult("tcp", port, FILTERED, service, None,
                          "no response (likely firewall/dropped)")
    except OSError as exc:
        if exc.errno in _FILTER_ERRNOS:
            return ScanResult("tcp", port, FILTERED, service, None,
                              f"network error: {exc.strerror or exc}")
        return ScanResult("tcp", port, UNKNOWN, service, None,
                          f"error: {exc.strerror or exc}")
    finally:
        sock.close()  # always release the socket (prevents resource leaks)


# ---------------------------------------------------------------------------
# UDP scanning (ordinary sockets - limited, see README)
# ---------------------------------------------------------------------------

def build_udp_probe(port: int) -> bytes:
    """Return a harmless, protocol-correct probe for a few well-known ports."""
    if port == 53:
        # Minimal DNS query for the name "localhost" (type A, class IN).
        return (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x09localhost\x00\x00\x01\x00\x01")
    if port == 123:
        # Standard 48-byte NTP client request (version 3, client mode).
        return b"\x1b" + b"\x00" * 47
    # Generic probe: one zero byte. Most services will simply ignore it.
    return b"\x00"


def scan_udp(ip: str, port: int, timeout: float) -> ScanResult:
    """Send a UDP probe and classify the outcome."""
    service = guess_service("udp", port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        # connect() on UDP does not send anything. It tells the OS to deliver
        # ICMP errors for this destination back to our socket.
        sock.connect((ip, port))
        start = time.perf_counter()
        sock.send(build_udp_probe(port))
        sock.recv(2048)  # wait for any reply
        rtt = (time.perf_counter() - start) * 1000
        return ScanResult("udp", port, OPEN, service, rtt,
                          "application replied")
    except socket.timeout:
        # Silence is ambiguous: open service that ignored us, OR filtered.
        return ScanResult("udp", port, OPEN_FILTERED, service, None,
                          "no response before timeout")
    except (ConnectionRefusedError, ConnectionResetError):
        # Linux: ECONNREFUSED. Windows: WSAECONNRESET. Both come from an
        # ICMP "port unreachable" message.
        return ScanResult("udp", port, CLOSED, service, None,
                          "ICMP port unreachable")
    except OSError as exc:
        if exc.errno in _FILTER_ERRNOS:
            return ScanResult("udp", port, FILTERED, service, None,
                              f"ICMP/network error: {exc.strerror or exc}")
        return ScanResult("udp", port, UNKNOWN, service, None,
                          f"error: {exc.strerror or exc}")
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Scan engine
# ---------------------------------------------------------------------------

def _worker(protocol: str, ip: str, port: int, timeout: float, delay: float,
            stop: threading.Event) -> Optional[ScanResult]:
    """Run one probe (skipped if the user pressed Ctrl+C)."""
    if stop.is_set():
        return None
    if delay > 0:
        time.sleep(delay)  # optional politeness delay (per worker thread)
    if protocol == "tcp":
        return scan_tcp(ip, port, timeout)
    return scan_udp(ip, port, timeout)


def run_scan(ip: str, protocols: List[str], ports: List[int], timeout: float,
             delay: float, workers: int) -> Tuple[List[ScanResult], bool]:
    """Scan all (protocol, port) pairs with a limited thread pool.

    Returns (results, interrupted).
    """
    jobs = [(proto, port) for proto in protocols for port in ports]
    total = len(jobs)
    results: List[ScanResult] = []
    stop = threading.Event()
    interrupted = False
    show_progress = total >= 50 and sys.stderr.isatty()

    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [executor.submit(_worker, p, ip, port, timeout, delay, stop)
                   for p, port in jobs]
        done = 0
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)
            done += 1
            if show_progress and (done % 10 == 0 or done == total):
                pct = done * 100 // total
                sys.stderr.write(f"\rProgress: {done}/{total} ({pct}%)")
                sys.stderr.flush()
    except KeyboardInterrupt:
        interrupted = True
        stop.set()  # tell workers to skip remaining jobs
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
        if show_progress:
            sys.stderr.write("\n")
    results.sort(key=lambda r: (r.protocol, r.port))
    return results, interrupted


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def format_row(r: ScanResult) -> str:
    """Format one result as an aligned text line."""
    rtt = f"{r.rtt_ms:.1f} ms" if r.rtt_ms is not None else "-"
    return (f"{r.protocol.upper():<6}{r.port:<7}{r.status:<15}"
            f"{r.service:<14}{rtt:<10}{r.note}")


def build_report(target: str, ip: str, results: List[ScanResult],
                 show_all: bool, interrupted: bool, elapsed: float) -> str:
    """Create the full text report (printed and optionally saved)."""
    lines = [
        "=" * 78,
        f"Scan report - {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Target: {target}   Resolved IP: {ip}",
        "=" * 78,
        f"{'PROTO':<6}{'PORT':<7}{'STATUS':<15}{'SERVICE*':<14}{'TIME':<10}NOTE",
        "-" * 78,
    ]
    # For big scans, hide the boring rows unless --show-all is used.
    hide = not show_all and len(results) > 50
    hidden = 0
    for r in results:
        if hide and r.status not in (OPEN, UNKNOWN):
            hidden += 1
            continue
        lines.append(format_row(r))
    if hidden:
        lines.append(f"... {hidden} closed/filtered/open|filtered rows hidden "
                     "(use --show-all to list them)")

    count = lambda s: sum(1 for r in results if r.status == s)  # noqa: E731
    lines += [
        "-" * 78,
        "SUMMARY",
        f"  Total ports scanned : {len(results)}",
        f"  Open                : {count(OPEN)}",
        f"  Closed              : {count(CLOSED)}",
        f"  Filtered            : {count(FILTERED)}",
        f"  Open|Filtered       : {count(OPEN_FILTERED)}",
        f"  Unknown             : {count(UNKNOWN)}",
        f"  Elapsed             : {elapsed:.1f} s",
    ]
    if interrupted:
        lines.append("  ** Scan interrupted by user - results are partial **")
    lines += [
        "",
        "* Service names are guesses based on the port number only. Any "
        "program can listen on any port.",
        "* UDP note: OPEN|FILTERED means silence. Ordinary sockets cannot tell "
        "an open UDP port that ignores the probe from a filtered one.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Safety checks and command line
# ---------------------------------------------------------------------------

def confirm(prompt: str, expected: str) -> bool:
    """Ask the user to type an exact word. Returns False on EOF/mismatch."""
    try:
        return input(prompt).strip() == expected
    except EOFError:
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tcp_udp_scanner.py",
        description="Educational TCP/UDP port scanner. Use ONLY on localhost, "
                    "lab machines, or systems you are authorized to test.",
        epilog="Examples:\n"
               "  python tcp_udp_scanner.py 127.0.0.1 --ports 22,80,443\n"
               "  python tcp_udp_scanner.py 127.0.0.1 --protocol both --common\n"
               "  python tcp_udp_scanner.py localhost --ports 1-100 --timeout 1.5",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="hostname or IPv4 address to scan")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--ports", type=ports_argument,
                       help="ports to scan, e.g. 80 or 22,80,443 or 1-1024 "
                            "or 22,80,8000-8100")
    group.add_argument("--common", action="store_true",
                       help="scan a list of common ports (default if no ports given)")
    group.add_argument("--all", action="store_true",
                       help="scan all ports 1-65535 (slow, asks for confirmation)")
    parser.add_argument("--protocol", choices=["tcp", "udp", "both"],
                        default="tcp", help="protocol to scan (default: tcp)")
    parser.add_argument("-t", "--timeout", type=positive_float,
                        default=DEFAULT_TIMEOUT,
                        help=f"seconds to wait per port (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-d", "--delay", type=non_negative_float, default=0.0,
                        help="seconds each worker waits before every probe "
                             "(default: 0)")
    parser.add_argument("-w", "--workers", type=workers_argument,
                        default=DEFAULT_WORKERS,
                        help=f"parallel threads, 1-{MAX_WORKERS} "
                             f"(default: {DEFAULT_WORKERS})")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="also save the report to a text file")
    parser.add_argument("--show-all", action="store_true",
                        help="list every port even in large scans")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="skip confirmation prompts (you confirm you are "
                             "authorized)")
    parser.add_argument("--version", action="version", version=VERSION)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    # 1. Decide which ports to scan.
    if args.all:
        ports = list(range(MIN_PORT, MAX_PORT + 1))
    elif args.ports:
        ports = args.ports
    else:
        ports = list(COMMON_PORTS)
    protocols = ["tcp", "udp"] if args.protocol == "both" else [args.protocol]

    # 2. Resolve the target.
    try:
        ip = resolve_target(args.target)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print("NOTICE: scan only systems you own or are authorized to test.")

    # 3. Ask for confirmation when the target is not local/private.
    addr = ipaddress.ip_address(ip)
    if not (addr.is_private or addr.is_loopback) and not args.yes:
        print(f"\n{ip} is a PUBLIC address.")
        if not confirm("Type 'I HAVE PERMISSION' to continue: ",
                       "I HAVE PERMISSION"):
            print("Aborted.")
            return 1

    # 4. Warn before large scans.
    total = len(ports) * len(protocols)
    if args.all and not args.yes:
        worst = total * args.timeout / args.workers
        print(f"\nWARNING: this will send {total} probes "
              f"(worst case about {worst / 60:.0f} minutes).")
        if not confirm("Type 'YES' to continue: ", "YES"):
            print("Aborted.")
            return 1

    print(f"Scanning {args.target} ({ip}) - {total} probe(s), "
          f"timeout {args.timeout}s, {args.workers} workers. Ctrl+C to stop.\n")

    # 5. Run the scan.
    started = time.perf_counter()
    results, interrupted = run_scan(ip, protocols, ports, args.timeout,
                                    args.delay, args.workers)
    elapsed = time.perf_counter() - started

    # 6. Print (and optionally save) the report.
    report = build_report(args.target, ip, results, args.show_all,
                          interrupted, elapsed)
    print(report)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(report + "\n")
            print(f"\nReport saved to {args.output}")
        except OSError as exc:
            print(f"\nError: could not write '{args.output}': {exc.strerror or exc}",
                  file=sys.stderr)
            return 3
    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(main())
