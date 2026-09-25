#!/usr/bin/env python3
"""
port_scanner.py
========================
A beginner-friendly, educational TCP "connect" port scanner.

Written for a university cybersecurity assignment using ONLY Python's
built-in `socket` library (no Nmap, no third-party scanning libraries).

--------------------------------------------------------------------------
ETHICAL / LEGAL USE NOTICE
--------------------------------------------------------------------------
Only run this scanner against systems you OWN or have EXPLICIT WRITTEN
PERMISSION to test (e.g. 127.0.0.1 / localhost, a lab VM, or a machine
your instructor has approved). Scanning systems without authorization can
violate the law (e.g. the UK Computer Misuse Act, the US Computer Fraud
and Abuse Act) as well as most university acceptable-use policies.
--------------------------------------------------------------------------

Usage examples:
    python port_scanner.py 127.0.0.1
    python port_scanner.py 127.0.0.1 -p 80
    python port_scanner.py 127.0.0.1 -p 1-1000
    python port_scanner.py 127.0.0.1 -p 22,80,443
    python port_scanner.py 127.0.0.1 -p 1-100 -t 0.5
"""

import argparse
import socket
import sys
import time
from datetime import datetime


# ==========================================================================
# 1. INPUT VALIDATION / PARSING HELPERS
# ==========================================================================

def resolve_target(target):
    """
    Resolve a hostname (e.g. 'example.com') OR an IP address (e.g.
    '127.0.0.1') into an IP address string that we can open sockets to.

    socket.gethostbyname() works for both cases: if you give it an IP
    address it simply hands it back after validating it; if you give it
    a hostname it performs a DNS lookup.

    Returns:
        str: the resolved IPv4 address.
    Raises:
        ValueError: if the target cannot be resolved.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(
            f"Could not resolve '{target}'. Check that the hostname or "
            f"IP address is spelled correctly."
        )


def _validate_port_number(port):
    """Raise ValueError if `port` is outside the valid TCP port range."""
    if not (1 <= port <= 65535):
        raise ValueError(f"Port {port} is out of range (valid range: 1-65535).")


def parse_ports(port_spec):
    """
    Turn a port specification string into a sorted list of unique port
    numbers.

    Supported formats (can be mixed together, separated by commas):
        "80"            -> [80]
        "1-1000"        -> [1, 2, ..., 1000]
        "22,80,443"     -> [22, 80, 443]
        "22,80-90,443"  -> [22, 80, 81, ..., 90, 443]

    Raises:
        ValueError: if any part of the specification is malformed.
    """
    ports = set()

    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue  # skip empty pieces caused by stray commas, e.g. "80,,443"

        if "-" in chunk:
            start_str, _, end_str = chunk.partition("-")
            start_str, end_str = start_str.strip(), end_str.strip()

            if not (start_str.isdigit() and end_str.isdigit()):
                raise ValueError(f"Invalid port range: '{chunk}'")

            start, end = int(start_str), int(end_str)
            _validate_port_number(start)
            _validate_port_number(end)

            if start > end:
                raise ValueError(
                    f"Invalid range '{chunk}': start port is larger than end port."
                )

            ports.update(range(start, end + 1))

        else:
            if not chunk.isdigit():
                raise ValueError(f"Invalid port number: '{chunk}'")
            port = int(chunk)
            _validate_port_number(port)
            ports.add(port)

    if not ports:
        raise ValueError("No valid ports were specified.")

    return sorted(ports)


# ==========================================================================
# 2. CORE SCANNING FUNCTIONS
# ==========================================================================

def get_service_name(port):
    """
    Look up the common/well-known service name for a TCP port using
    Python's built-in services database (e.g. 80 -> 'http').

    Returns 'unknown' if no matching service is registered on this system.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(ip, port, timeout):
    """
    Perform a TCP "connect" scan against a single port.

    A full TCP three-way handshake is attempted. If it succeeds, the port
    is OPEN (something is listening). If the connection is refused or
    times out, the port is treated as CLOSED (or filtered by a firewall).

    Returns:
        bool: True if the port is open, False otherwise.
    """
    # socket.AF_INET     -> use IPv4 addressing
    # socket.SOCK_STREAM -> use TCP (a "stream" / connection-based protocol)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # connect_ex() returns 0 on a successful connection, or a non-zero
        # error code otherwise. It's used instead of connect() so we don't
        # need a try/except for every single "connection refused" result.
        error_code = sock.connect_ex((ip, port))
        return error_code == 0


def run_scan(target, ip, ports, timeout):
    """
    Scan every port in `ports` against `ip`, showing a live progress
    message, and return the results.

    Returns:
        tuple: (list of (port, status, service) tuples, elapsed seconds)
    """
    results = []
    total_ports = len(ports)
    start_time = time.time()

    for index, port in enumerate(ports, start=1):
        # --- simple progress indicator -------------------------------
        # "\r" moves the cursor back to the start of the line, so each
        # update overwrites the previous one instead of printing a new
        # line for every single port that is checked.
        print(f"Scanning port {port:<6} ({index}/{total_ports})", end="\r")
        sys.stdout.flush()

        is_open = scan_port(ip, port, timeout)
        service = get_service_name(port) if is_open else "-"
        status = "OPEN" if is_open else "CLOSED"
        results.append((port, status, service))

    # Clear the progress line once scanning has finished.
    print(" " * 40, end="\r")

    elapsed = time.time() - start_time
    return results, elapsed


# ==========================================================================
# 3. OUTPUT / DISPLAY FUNCTIONS
# ==========================================================================

def print_header(target, ip, ports, timeout):
    """Print a short banner describing the scan that is about to run."""
    print("=" * 60)
    print("  SIMPLE TCP PORT SCANNER (educational use only)")
    print("=" * 60)
    print(f"Target        : {target} ({ip})")
    print(f"Ports to scan : {len(ports)}")
    print(f"Timeout       : {timeout} seconds per port")
    print(f"Start time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)


def print_results(target, results):
    """Print a formatted table of Target / Port / Status / Service."""
    print(f"{'TARGET':<16}{'PORT':<8}{'STATUS':<10}{'SERVICE':<15}")
    print("-" * 60)
    for port, status, service in results:
        print(f"{target:<16}{port:<8}{status:<10}{service:<15}")


def print_summary(results, elapsed):
    """Print a short summary of how many ports were open/closed."""
    open_ports = [r for r in results if r[1] == "OPEN"]
    closed_ports = [r for r in results if r[1] == "CLOSED"]

    print("-" * 60)
    print(f"Scan finished in {elapsed:.2f} seconds.")
    print(f"Open ports   : {len(open_ports)}")
    print(f"Closed ports : {len(closed_ports)}")

    if open_ports:
        print("\nOpen ports found:")
        for port, status, service in open_ports:
            print(f"  - {port}/tcp ({service})")
    else:
        print("\nNo open ports found in the scanned range.")


# ==========================================================================
# 4. COMMAND-LINE INTERFACE
# ==========================================================================

def build_arg_parser():
    """Configure and return the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="A simple, educational TCP connect port scanner.",
        epilog="Example: python port_scanner.py 127.0.0.1 -p 1-1000",
    )
    parser.add_argument(
        "target",
        help="Target IP address or hostname (e.g. 127.0.0.1 or example.com)",
    )
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Port(s) to scan: a single port ('80'), a range ('1-1000'), "
             "or a comma-separated list ('22,80,443'). Default: 1-1024.",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds per port (default: 1.0). "
             "Lower values scan faster but may miss slow-to-respond ports.",
    )
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    # --- Step 1: validate/resolve the target -----------------------------
    try:
        ip = resolve_target(args.target)
    except ValueError as err:
        print(f"Error: {err}")
        sys.exit(1)

    # --- Step 2: validate/parse the port specification --------------------
    try:
        ports = parse_ports(args.ports)
    except ValueError as err:
        print(f"Error: {err}")
        sys.exit(1)

    # --- Step 3: validate the timeout --------------------------------------
    if args.timeout <= 0:
        print("Error: timeout must be a positive number of seconds.")
        sys.exit(1)

    # --- Step 4: run the scan ------------------------------------------------
    print_header(args.target, ip, ports, args.timeout)

    try:
        results, elapsed = run_scan(args.target, ip, ports, args.timeout)
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user (Ctrl+C). Exiting.")
        sys.exit(1)
    except socket.error as err:
        # Catches unexpected low-level networking errors (e.g. network
        # unreachable, too many open sockets, etc.)
        print(f"\nNetwork error during scan: {err}")
        sys.exit(1)

    # --- Step 5: display the results ------------------------------------------
    print_results(args.target, results)
    print_summary(results, elapsed)


if __name__ == "__main__":
    main()
