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
  python3 nsgscanner.py --interactive    # pick a host from the ARP table, live scan

Note: use it only against hosts you own or are explicitly authorized to test.
UDP scanning is inherently ambiguous (connectionless): with no reply you cannot
tell "open" from "filtered" -> state open|filtered.
"""
import argparse, errno, os, queue, shutil, socket, subprocess, sys, time
import concurrent.futures as cf

__version__ = "1.2.1"

DEFAULT_PORTS = "1-1024"      # interactive mode: initial port suggestion
LIVE_ALL_MAX = 64             # interactive mode: show every result live up to N ports

STATE_ORDER = ("open", "open|filtered", "closed", "filtered", "error")
STATE_COLORS = {"open": "1;32", "open|filtered": "36", "closed": "2",
                "filtered": "33", "error": "31"}


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
    """Accepts '502', '80,443,502' or '1-1024' (and mixes of these).
    Raises ValueError on non-numeric input."""
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


# --------------------------------------------------------------------------
# probes
# --------------------------------------------------------------------------

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


def scan_iter(ip, ports, proto, timeout, workers, banner=False, tick=0.25):
    """Scan in parallel and yield (port, (state, rtt, extra)) as each probe
    completes. Yields None every `tick` seconds with no result, so a caller
    can refresh a live display. Pending probes are cancelled on exit."""
    if proto == "tcp":
        work = lambda p: scan_tcp(ip, p, timeout, banner)
    else:
        work = lambda p: scan_udp(ip, p, timeout)
    ex = cf.ThreadPoolExecutor(max_workers=max(1, min(workers, len(ports))))
    done_q = queue.Queue()
    fut = {}
    try:
        for p in ports:
            f = ex.submit(work, p)
            fut[f] = p
            f.add_done_callback(done_q.put)
        remaining = len(fut)
        while remaining:
            try:
                f = done_q.get(timeout=tick)
            except queue.Empty:
                yield None
                continue
            remaining -= 1
            yield fut[f], f.result()
    finally:
        for f in fut:
            f.cancel()
        ex.shutdown(wait=False)


# --------------------------------------------------------------------------
# output helpers
# --------------------------------------------------------------------------

def fmt_line(port, proto, state, rtt, extra, color=False):
    st = "%-13s" % state if (rtt is not None or extra) else state
    if color and state in STATE_COLORS:
        st = "\033[%sm%s\033[0m" % (STATE_COLORS[state], st)
    line = "%5d/%s  %s" % (port, proto, st)
    if rtt is not None:
        line += "  %6.1f ms" % rtt
    if extra:
        line += "  %s" % extra
    return line


def fmt_counts(counts):
    return ", ".join("%s %d" % (s, counts[s])
                     for s in STATE_ORDER if counts.get(s)) or "-"


def status_text(done, total, counts, t0, width=20):
    fill = width * done // total if total else width
    txt = "[%s%s] %d/%d %3d%% | %s | %.1fs" % (
        "#" * fill, "." * (width - fill), done, total,
        100 * done // total if total else 100, fmt_counts(counts),
        time.time() - t0)
    cols = shutil.get_terminal_size((80, 24)).columns
    return txt[:max(10, cols - 1)]           # never wrap, or \r can't redraw it


# --------------------------------------------------------------------------
# interactive mode
# --------------------------------------------------------------------------

def _ip_key(ip):
    try:
        return socket.inet_aton(ip)
    except OSError:
        return b"\xff\xff\xff\xff"


def arp_hosts():
    """Directly connected IPv4 neighbours from the ARP table, as a sorted
    list of (ip, mac, dev, state). Uses `ip neigh`, falls back to
    /proc/net/arp when the `ip` command is not available."""
    hosts = {}
    try:
        out = subprocess.run(["ip", "neigh", "show"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL,
                             universal_newlines=True, timeout=5).stdout
        for line in out.splitlines():
            tok = line.split()
            if not tok or ":" in tok[0] or "lladdr" not in tok:
                continue                      # IPv6 or no MAC (FAILED/INCOMPLETE)
            state = tok[-1] if tok[-1].isupper() else ""
            if state in ("FAILED", "INCOMPLETE"):
                continue
            i = tok.index("lladdr") + 1
            mac = tok[i].lower() if i < len(tok) else "?"
            dev = tok[tok.index("dev") + 1] if "dev" in tok[:-1] else ""
            hosts[tok[0]] = (tok[0], mac, dev, state)
    except (OSError, subprocess.SubprocessError):
        pass
    if not hosts:
        try:
            with open("/proc/net/arp") as f:
                next(f, None)                 # header line
                for line in f:
                    tok = line.split()
                    # IP, HW type, Flags, HW address, Mask, Device
                    if (len(tok) >= 6 and tok[2] != "0x0"
                            and tok[3] != "00:00:00:00:00:00"):
                        hosts[tok[0]] = (tok[0], tok[3].lower(), tok[5], "")
        except OSError:
            pass
    return sorted(hosts.values(), key=lambda h: _ip_key(h[0]))


def getkey(prompt=""):
    """Read a single keypress. cbreak mode keeps Ctrl+C (SIGINT) working.
    Returns '' for Enter/space; falls back to line input without a tty."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        import termios, tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
    except Exception:                         # not a tty / not POSIX
        line = sys.stdin.readline()
        if not line:
            raise EOFError
        return line.strip()[:1]
    try:
        tty.setcbreak(fd)
        data = os.read(fd, 32)                # swallow escape sequences whole
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    if not data or data[:1] == b"\x04":       # EOF / Ctrl+D
        raise EOFError
    ch = data[:1].decode("latin-1")
    print(ch if ch.isprintable() else "")
    return ch.strip()


def manual_host():
    while True:
        h = input("Host (IP or name, Enter=back): ").strip()
        if not h:
            return None
        try:
            ip = socket.gethostbyname(h)
        except (socket.gaierror, UnicodeError) as e:
            print("  name resolution failed: %s" % e)
            continue
        return ip, (ip if h == ip else "%s (%s)" % (h, ip))


def pick_from_arp():
    while True:
        hosts = arp_hosts()
        print()
        if hosts:
            print("  %3s  %-15s  %-19s  %-10s  %s"
                  % ("#", "IP", "(MAC)", "IFACE", "STATE"))
            for i, (ip, mac, dev, st) in enumerate(hosts, 1):
                print("  %3d  %-15s  %-19s  %-10s  %s"
                      % (i, ip, "(%s)" % mac, dev, st))
            hint = "Select host [1-%d], r=refresh, m=manual, Enter=back: " % len(hosts)
        else:
            print("  ARP table is empty (only hosts this system talked to "
                  "recently are listed).")
            hint = "r=refresh, m=manual, Enter=back: "
        s = input(hint).strip().lower()
        if not s:
            return None
        if s == "r":
            continue
        if s == "m":
            target = manual_host()
            if target:
                return target
            continue
        if s.isdigit() and 1 <= int(s) <= len(hosts):
            ip, mac = hosts[int(s) - 1][:2]
            return ip, "%s (%s)" % (ip, mac)
        print("  invalid choice")


def live_scan(ip, label, ports, proto, opts, ansi, color):
    """Run a scan printing results as they arrive, with a progress line.
    Ctrl+C stops the scan and returns to the caller."""
    total = len(ports)
    show_all = total <= LIVE_ALL_MAX
    print("# target %s | %s | %d port(s) | timeout %.1fs | Ctrl+C stops the scan"
          % (label, proto.upper(), total, opts.timeout))
    if not show_all:
        print("# more than %d ports: only open ports are listed live, "
              "every state is counted" % LIVE_ALL_MAX)
    counts, opened = {}, []
    done, last, shown, aborted = 0, 0.0, False, False
    t0 = time.time()
    it = scan_iter(ip, ports, proto, opts.timeout, opts.workers, opts.banner)
    try:
        for item in it:
            printed = False
            if item is not None:
                port, (state, rtt, extra) = item
                done += 1
                counts[state] = counts.get(state, 0) + 1
                if state == "open":
                    opened.append(port)
                if show_all or state == "open":
                    if shown:
                        sys.stdout.write("\r\033[K")
                    print(fmt_line(port, proto, state, rtt, extra, color))
                    printed = True
            now = time.time()
            if ansi and (printed or done == total or now - last >= 0.1):
                sys.stdout.write("\r\033[K" + status_text(done, total, counts, t0))
                sys.stdout.flush()
                shown, last = True, now
    except KeyboardInterrupt:
        aborted = True
    finally:
        it.close()
    if shown:
        sys.stdout.write("\r\033[K")
    if aborted:
        print("# aborted after %d/%d port(s)" % (done, total))
    print("# %d/%d scanned | %s | %.2fs"
          % (done, total, fmt_counts(counts), time.time() - t0))
    if opened and not show_all:
        print("# open: %s" % ",".join(str(p) for p in sorted(opened)))


def scan_loop(target, opts, st, ansi, color):
    ip, label = target
    while True:
        print()
        print("Target: %s" % label)
        while True:
            spec = input("Ports [%s]: " % st["ports"]).strip() or st["ports"]
            try:
                ports = parse_ports(spec)
            except ValueError:
                ports = []
            if ports:
                break
            print("  invalid ports (examples: 502 | 80,443 | 1-1024)")
        st["ports"] = spec
        k = getkey("Protocol [t]cp / [u]dp (Enter = %s): " % st["proto"]).lower()
        if k in ("t", "u"):
            st["proto"] = "tcp" if k == "t" else "udp"
        live_scan(ip, label, ports, st["proto"], opts, ansi, color)
        print()
        k = getkey("[Enter] new scan on this host   [l] host list   "
                   "(Ctrl+C exit): ").lower()
        if k == "l":
            return


def interactive(opts):
    try:
        __import__("readline")                # line editing for input(), if present
    except ImportError:
        pass
    ansi = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
    color = ansi and "NO_COLOR" not in os.environ
    title = "nsgscanner %s - interactive mode" % __version__
    print(("\033[1m%s\033[0m" % title if color else title) + "   (Ctrl+C to exit)")
    print("# timeout %.1fs | workers %d | banner %s"
          % (opts.timeout, opts.workers, "on" if opts.banner else "off"))
    st = {"ports": DEFAULT_PORTS, "proto": opts.proto}
    try:
        while True:
            print()
            k = getkey("Press any key to list directly connected hosts "
                       "(ARP table), [m] to type a host: ").lower()
            target = manual_host() if k == "m" else pick_from_arp()
            if target:
                scan_loop(target, opts, st, ansi, color)
    except (KeyboardInterrupt, EOFError):
        print("\n# bye")
        sys.stdout.flush()
        os._exit(0)                           # don't wait for probes in flight


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------

HELP_DESCRIPTION = """\
TCP/UDP port scanner to support troubleshooting performed from
Netskope Smart Gateways (NSG), formerly Infiot.

Two ways to run it:
  nsgscanner <host> <ports> [options]   one-shot scan, results at the end
  nsgscanner -i [options]               interactive menu with live scan"""

HELP_EPILOG = """\
examples:
  nsgscanner 192.168.55.56 502                     single TCP port
  nsgscanner 192.168.55.56 80,443,502 --banner     port list + banner grab
  nsgscanner 192.168.55.56 1-1024 --open-only      port range, open only
  nsgscanner 192.168.55.56 53 --proto udp          UDP
  nsgscanner -i                                    interactive menu
  nsgscanner -i --timeout 1 --banner               interactive, options
                                                   applied to every scan

interactive mode (-i / --interactive):
  1. press any key to list the directly connected hosts from the ARP
     table (ip neigh, or /proc/net/arp) as IP (MAC), or [m] to type a host
  2. pick a host by number, then enter the ports and the protocol
  3. results appear live, with a progress line and per-state counters
     (above 64 ports only open ports are listed, all states are counted)
  Ctrl+C stops a running scan; Ctrl+C at the menu exits.
  The ARP table only lists hosts the gateway talked to recently.

port states:
  TCP  open           connection accepted
       closed         actively refused (RST)
       filtered       no reply within the timeout (firewall drop)
       error          other failure, errno shown (e.g. EHOSTUNREACH)
  UDP  open           application reply received
       closed         ICMP port-unreachable received
       open|filtered  no reply (cannot tell open from filtered)

Use only against hosts you own or are explicitly authorized to test."""


def main():
    ap = argparse.ArgumentParser(
        prog="nsgscanner",
        description=HELP_DESCRIPTION, epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host", nargs="?", help="target IP or hostname")
    ap.add_argument("ports", nargs="?",
                    help="single port (502), list (80,443) or range (1-1024)")
    ap.add_argument("-i", "--interactive", action="store_true",
                    help="interactive menu: pick a host from the ARP table, "
                         "choose ports/protocol, watch the scan live "
                         "(Ctrl+C to exit)")
    ap.add_argument("--proto", choices=["tcp", "udp"], default="tcp",
                    help="protocol (default: tcp; selectable in the menu "
                         "with -i)")
    ap.add_argument("--timeout", type=float, default=1.5,
                    help="per-port timeout in seconds (default: 1.5)")
    ap.add_argument("--workers", type=int, default=100,
                    help="parallel scans (default: 100)")
    ap.add_argument("--banner", action="store_true",
                    help="TCP: attempt a banner grab on open ports")
    ap.add_argument("--open-only", action="store_true",
                    help="print open ports only (one-shot scan)")
    ap.add_argument("--version", action="version",
                    version="nsgscanner " + __version__)
    if len(sys.argv) == 1:                   # no arguments: show the full help
        ap.print_help()
        sys.exit(0)
    args = ap.parse_args()

    if args.interactive:
        if args.host or args.ports:
            ap.error("--interactive does not take host/ports arguments")
        interactive(args)
        return
    if not args.host or not args.ports:
        ap.error("host and ports are required (or use --interactive)")

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror as e:
        print("Name resolution failed for %s: %s" % (args.host, e))
        sys.exit(2)

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        ports = []
    if not ports:
        print("No valid port in '%s'" % args.ports)
        sys.exit(2)

    print("# target %s (%s) | %s | %d port(s) | timeout %.1fs"
          % (args.host, ip, args.proto.upper(), len(ports), args.timeout))

    t0 = time.time()
    results = {}
    try:
        for item in scan_iter(ip, ports, args.proto, args.timeout,
                              args.workers, args.banner):
            if item is not None:
                results[item[0]] = item[1]
    except KeyboardInterrupt:
        print("\n# aborted")
        sys.stdout.flush()
        os._exit(130)       # exit now, don't wait for in-flight probes

    openc = 0
    for p in ports:
        state, rtt, extra = results[p]
        is_open = state.startswith("open")
        openc += is_open
        if args.open_only and not is_open:
            continue
        print(fmt_line(p, args.proto, state, rtt, extra))
    print("# %d open (or open|filtered) of %d | %.2fs"
          % (openc, len(ports), time.time() - t0))


if __name__ == "__main__":
    main()
