#!/usr/bin/env python3
"""Tiny local test services so you can safely try the scanner.

Starts a TCP listener on 8080 and a UDP echo server on 9999 (localhost only).
Press Ctrl+C to stop.
"""

import socket
import threading

HOST = "127.0.0.1"
TCP_PORT = 8080
UDP_PORT = 9999


def tcp_listener() -> None:
    """Accept TCP connections and immediately close them."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, TCP_PORT))
        srv.listen(50)
        while True:
            conn, _ = srv.accept()
            conn.close()


def udp_echo() -> None:
    """Reply to every UDP datagram with the same bytes."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
        srv.bind((HOST, UDP_PORT))
        while True:
            data, addr = srv.recvfrom(2048)
            srv.sendto(data, addr)


if __name__ == "__main__":
    threading.Thread(target=tcp_listener, daemon=True).start()
    threading.Thread(target=udp_echo, daemon=True).start()
    print(f"TCP listening on {HOST}:{TCP_PORT}, UDP echo on {HOST}:{UDP_PORT}")
    print("Press Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nStopped.")
