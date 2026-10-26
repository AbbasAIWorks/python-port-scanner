# TCP/UDP Port Scanner (Educational)

A beginner-friendly command-line port scanner written in pure Python (standard library only).

> **Use only on localhost, lab machines, or systems you own or have written permission to test.**
> Unauthorized scanning may be illegal. This tool has no stealth, evasion, exploit, or DoS features.

## Project structure

```
tcp_udp_scanner/
├── tcp_udp_scanner.py   # the scanner
├── test_server.py       # local test services (TCP 8080, UDP 9999)
├── README.md
└── .gitignore
```

## How scanning works

**TCP (connect scan):** The scanner tries a normal TCP connection to each port.
- Connection accepted -> **OPEN**
- Connection refused (RST) -> **CLOSED**
- No answer before timeout -> **FILTERED** (a firewall is probably dropping packets)
- Other errors -> **UNKNOWN**

**UDP:** UDP has no handshake. The scanner sends a small datagram and listens.
- Application replies -> **OPEN**
- ICMP "port unreachable" received -> **CLOSED**
- ICMP/network error such as host unreachable or admin-prohibited -> **FILTERED**
- Silence until timeout -> **OPEN|FILTERED** (cannot tell which)

Service names (ssh, http, ...) are **guesses from the port number only**. Any program can listen on any port.

## Setup

Requires **Python 3.9+**. No packages to install, and no admin/root needed.

**Windows 11**
1. Install Python from https://www.python.org/downloads/ (tick "Add python.exe to PATH").
2. Open PowerShell in the project folder and check: `python --version`
3. Run commands with `python tcp_udp_scanner.py ...`

**Kali Linux**
1. Python 3 is preinstalled. Check: `python3 --version`
2. Run commands with `python3 tcp_udp_scanner.py ...`

## Commands

```
python tcp_udp_scanner.py --help
python tcp_udp_scanner.py 127.0.0.1 --ports 22,80,443
python tcp_udp_scanner.py 127.0.0.1 --ports 1-100
python tcp_udp_scanner.py 127.0.0.1 --ports 22,80,8000-8100
python tcp_udp_scanner.py 127.0.0.1 --protocol tcp
python tcp_udp_scanner.py 127.0.0.1 --protocol udp
python tcp_udp_scanner.py 127.0.0.1 --protocol both
python tcp_udp_scanner.py 127.0.0.1 --common
python tcp_udp_scanner.py 127.0.0.1 --ports 1-100 --timeout 1.5
python tcp_udp_scanner.py 127.0.0.1 --protocol both --output results.txt
python tcp_udp_scanner.py 127.0.0.1 --all          # asks for confirmation
python tcp_udp_scanner.py 127.0.0.1 --ports 1-500 --delay 0.05 --workers 20
```

| Option | Meaning |
|---|---|
| `-p, --ports` | Single port, list, range, or mix |
| `--common` | Common ports (also the default) |
| `--all` | Ports 1-65535 (warns first) |
| `--protocol` | `tcp` (default), `udp`, `both` |
| `-t, --timeout` | Seconds per port (default 1.0, max 60) |
| `-d, --delay` | Seconds each worker waits before every probe |
| `-w, --workers` | Threads, 1-500 (default 50) |
| `-o, --output` | Save the report to a file |
| `--show-all` | Show every row in big scans |
| `-y, --yes` | Skip confirmation prompts |

Public (non-private) IPs require typing `I HAVE PERMISSION` unless `--yes` is used.

## Example output

```
PROTO PORT   STATUS         SERVICE*      TIME      NOTE
------------------------------------------------------------------------------
TCP   22     CLOSED         ssh           0.1 ms    connection refused
TCP   8080   OPEN           http-alt      0.0 ms    connection accepted
TCP   9000   FILTERED       unknown       -         no response (likely firewall/dropped)
UDP   9999   OPEN           unknown       0.0 ms    application replied
UDP   9998   OPEN|FILTERED  unknown       -         no response before timeout
UDP   8081   CLOSED         unknown       -         ICMP port unreachable
------------------------------------------------------------------------------
SUMMARY
  Total ports scanned : 6
  Open                : 2
  Closed              : 2
  Filtered            : 1
  Open|Filtered       : 1
  Unknown             : 0
```

## Safe testing on 127.0.0.1

1. Terminal 1: `python test_server.py` (TCP 8080 and UDP echo 9999)
2. Terminal 2: `python tcp_udp_scanner.py 127.0.0.1 --protocol both --ports 8080,9999,8081`
3. Expect TCP 8080 OPEN, UDP 9999 OPEN, and the others CLOSED.

## Troubleshooting

| Problem | Fix |
|---|---|
| `python` not recognized (Windows) | Reinstall Python with "Add to PATH", or use `py tcp_udp_scanner.py ...` |
| `cannot resolve '...'` | Check spelling, DNS, or use an IP address |
| `outside 1-65535` / `empty entry` | Fix the port list (no trailing commas) |
| Everything FILTERED | A firewall is dropping traffic, or the host is down; try a larger `--timeout` |
| UDP scan is slow | Silent ports wait the full timeout; lower `--timeout` or scan fewer ports |
| Every UDP port shows OPEN\|FILTERED | Normal for hosts that do not send ICMP errors |
| `could not write file` | Check folder exists and you have write permission |
| Errors about too many open files | Lower `--workers` |

## Testing status

Tested on Linux (Python 3.12) against localhost: TCP open/closed, UDP open/closed/open|filtered, argument validation, confirmation prompts, and report export. **Not tested on Windows 11.** The code handles Windows error codes (WSAECONNRESET, WSA 10051/10065/10013), but verify on your machine.

## Known limitations

- UDP with ordinary sockets is unreliable: silence cannot distinguish open from filtered, and ICMP reporting depends on the OS (Linux: connection refused; Windows: connection reset, which can be inconsistent).
- Only a few UDP services get protocol-correct probes (DNS, NTP); others get one null byte.
- ICMP "port unreachable" can also be generated by a firewall that rejects traffic, so CLOSED is not proof that no firewall exists.
- Connect scans are visible in target logs.
- IPv4 only; one target per run; `--delay` is per worker thread.
- No banner grabbing or version detection.

## Possible improvements

IPv6 support, multiple targets/CIDR ranges, banner grabbing, more UDP probes, JSON/CSV export, a global rate limiter, optional raw-socket ICMP listener (needs admin rights), unit tests.

## Uploading to GitHub (copy-paste method)

1. Sign in at https://github.com and click **+ -> New repository**.
2. Name it `tcp-udp-scanner`, choose Public or Private, tick **Add a README file**, click **Create repository**.
3. In the repo, click **Add file -> Create new file**.
4. In the filename box type `tcp_udp_scanner.py`, then paste the full code into the editor.
5. Scroll down, click **Commit changes**, then **Commit changes** again.
6. Repeat steps 3-5 for `test_server.py` and `.gitignore`.
7. To replace the default README: open `README.md`, click the pencil icon, paste this file's contents, commit.

On a phone, use the browser (desktop site mode helps) since the GitHub app cannot create new files as easily.
