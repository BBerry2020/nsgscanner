#!/usr/bin/env python3
#
# nsgscanner - minimal TCP/UDP port scanner
# Copyright (c) 2026 BBerry2020
# SPDX-License-Identifier: MIT
# See the LICENSE file for the full license text.
#
"""
nsgscanner.py - minimal TCP/UDP scanner for a host and one or more ports.

A tool to support troubleshooting performed from Netskope Smart Gateways
(NSG), formerly Infiot: check from the gateway whether a host:port answers,
refuses the connection, or is silently dropped.

Examples:
  python3 nsgscanner.py 192.168.55.56 502
  python3 nsgscanner.py 192.168.55.56 80,443,502 --proto tcp --banner
  python3 nsgscanner.py 192.168.55.56 1-1024 --proto tcp --timeout 1 --workers 200 --open-only
  python3 nsgscanner.py 192.168.55.56 53 --proto udp

Note: use it only against hosts you own or are explicitly authorized to test.
UDP scanning is inherently ambiguous (connectionless): with no reply you cannot
tell "open" from "filtered" -> state open|filtered.
"""
import argparse, errno, os, socket, sys, time
import concurrent.futures as cf

__version__ = "1.1.0"


def _codes(*names):
    return {getattr(errno, n) for n in names if hasattr(errno, n)}


# connect_ex() does NOT raise socket.timeout: when the timeout expires it
# returns an errno (EAGAIN/EWOULDBLOCK on Linux, WSAEWOULDBLOCK on Windows).
REFUSED = _codes("ECONNREFUSED", "WSAECONNREFUSED")
TIMED_OUT = _codes("EAGAIN", "EWOULDBLOCK", "EINPROGRESS", "ETIMEDOUT",
                   "WSAEWOULDBLOCK", "WSAETIMEDOUT")


def errname(code):
    """errno code -> 'EHOSTUNREACH (No route to host)'."""
    if not code:
        return "unknown error"
    return "%s (%s)" % (errno.errorcode.get(code, code), os.strerror(code))


def parse_ports(spec):
    """Accepts '502', '80,443,502' or '1-1024' (and mixes of these)."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            ports.update(range(min(a, b), max(a, b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)


def scan_tcp(ip, port, timeout, grab=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        t0 = time.time()
        rc = s.connect_ex((ip, port))          # 0 = connected, else errno
        rtt = (time.time() - t0) * 1000
        if rc == 0:
            banner = ""
            if grab:
                try:
                    s.settimeout(min(timeout, 1.0))
                    banner = s.recv(128).decode("latin-1", "replace").strip()
                except OSError:
                    banner = ""
            return ("open", rtt, banner)
        if rc in REFUSED:
            return ("closed", rtt, "")          # actively refused (RST)
        if rc in TIMED_OUT:
            return ("filtered", None, "")       # no reply (firewall drop)
        return ("error", rtt, errname(rc))      # e.g. EHOSTUNREACH, ENETUNREACH
    except socket.timeout:
        return ("filtered", None, "")
    except OSError as e:
        return ("error", None, errname(e.errno) if e.errno else str(e))
    finally:
        s.close()


def scan_udp(ip, port, timeout, payload=b"\x00"):
    # connect() on the UDP socket makes an ICMP port-unreachable surface as
    # ConnectionRefusedError (Linux) or ConnectionResetError (Windows).
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.send(payload)
        try:
            data = s.recv(512)
            return ("open", None, data[:64].hex())          # application reply
        except socket.timeout:
            return ("open|filtered", None, "")              # no reply
        except (ConnectionRefusedError, ConnectionResetError):
            return ("closed", None, "")                     # ICMP unreachable
    except OSError as e:
        return ("error", None, errname(e.errno) if e.errno else str(e))
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(
        prog="nsgscanner",
        description="TCP/UDP scanner against host:port, to support "
                    "troubleshooting from Netskope Smart Gateways "
                    "(NSG, formerly Infiot).")
    ap.add_argument("host", help="target IP or hostname")
    ap.add_argument("ports", help="single port, list (80,443) or range (1-1024)")
    ap.add_argument("--proto", choices=["tcp", "udp"], default="tcp",
                    help="protocol (default: tcp)")
    ap.add_argument("--timeout", type=float, default=1.5,
                    help="per-port timeout in seconds (default: 1.5)")
    ap.add_argument("--workers", type=int, default=100,
                    help="parallel scans (default: 100)")
    ap.add_argument("--banner", action="store_true",
                    help="TCP: attempt a banner grab on open ports")
    ap.add_argument("--open-only", action="store_true",
                    help="print open ports only")
    ap.add_argument("--version", action="version",
                    version="nsgscanner " + __version__)
    args = ap.parse_args()

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror as e:
        print("Name resolution failed for %s: %s" % (args.host, e))
        sys.exit(2)

    ports = parse_ports(args.ports)
    if not ports:
        print("No valid port in '%s'" % args.ports)
        sys.exit(2)

    print("# target %s (%s) | %s | %d port(s) | timeout %.1fs"
          % (args.host, ip, args.proto.upper(), len(ports), args.timeout))

    if args.proto == "tcp":
        work = lambda p: scan_tcp(ip, p, args.timeout, args.banner)
    else:
        work = lambda p: scan_udp(ip, p, args.timeout)

    t0 = time.time()
    results = {}
    fut = {}
    workers = max(1, min(args.workers, len(ports)))
    ex = cf.ThreadPoolExecutor(max_workers=workers)
    try:
        fut = {ex.submit(work, p): p for p in ports}
        for f in cf.as_completed(fut):
            results[fut[f]] = f.result()
    except KeyboardInterrupt:
        for f in fut:
            f.cancel()
        print("\n# aborted")
        sys.stdout.flush()
        os._exit(130)       # exit now, don't wait for in-flight probes
    ex.shutdown()

    openc = 0
    for p in ports:
        state, rtt, extra = results[p]
        is_open = state.startswith("open")
        openc += is_open
        if args.open_only and not is_open:
            continue
        line = "%5d/%s  %-13s" % (p, args.proto, state)
        if rtt is not None:
            line += "  %6.1f ms" % rtt
        if extra:
            line += "  %s" % extra
        print(line.rstrip())
    print("# %d open (or open|filtered) of %d | %.2fs"
          % (openc, len(ports), time.time() - t0))


if __name__ == "__main__":
    main()
