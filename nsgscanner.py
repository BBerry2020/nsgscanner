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
import argparse, errno, ipaddress, os, queue, re, shutil, socket, struct
import subprocess, sys, time
import concurrent.futures as cf

__version__ = "1.3.0"

DEFAULT_PORTS = "1-1024"      # interactive mode: initial port suggestion
DEFAULT_NET_PORTS = "22,80,443"   # interactive "TCP port on all hosts" suggestion
LIVE_ALL_MAX = 64             # interactive mode: show every result live up to N ports
CONFIRM_ABOVE = 1024          # ask before running more probes than this
MIN_PREFIX = 16               # largest network accepted for checks on all hosts

STATE_ORDER = ("open", "open|filtered", "closed", "filtered", "error")
PING_ORDER = ("alive", "no reply", "error")
STATE_COLORS = {"open": "1;32", "open|filtered": "36", "closed": "2",
                "filtered": "33", "error": "31", "alive": "1;32",
                "arp-only": "33", "no reply": "2"}


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


PING_RTT = re.compile(r"time[=<]\s*([\d.]+)\s*ms")
_ping_base = []


def ping_cmd():
    """Base ping command for this system ('-n' when supported), None if
    the ping command is missing."""
    if not _ping_base:
        if not shutil.which("ping"):
            _ping_base.append(None)
        else:
            try:
                rc = subprocess.run(["ping", "-n", "-c", "1", "-W", "1",
                                     "127.0.0.1"], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                    timeout=5).returncode
            except (OSError, subprocess.SubprocessError):
                rc = 1
            _ping_base.append(["ping", "-n"] if rc == 0 else ["ping"])
    return _ping_base[0]


def ping_host(ip, timeout, base):
    """One ICMP echo through the system ping command (no root needed)."""
    cmd = base + ["-c", "1", "-W", str(timeout), ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True,
                           timeout=timeout + 3)
    except subprocess.TimeoutExpired:
        return ("no reply", None, "")
    except OSError as e:
        return ("error", None, str(e))
    m = PING_RTT.search(r.stdout)
    if r.returncode == 0 and m:
        return ("alive", float(m.group(1)), "")
    return ("no reply", None, "")


def run_parallel(tasks, work, workers, tick=0.25):
    """Run work(task) in parallel and yield (task, result) as each one
    completes. Yields None every `tick` seconds with no result, so a caller
    can refresh a live display. Pending tasks are cancelled on exit."""
    ex = cf.ThreadPoolExecutor(max_workers=max(1, min(workers, len(tasks))))
    done_q = queue.Queue()
    fut = {}
    try:
        for t in tasks:
            f = ex.submit(work, t)
            fut[f] = t
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


def scan_iter(ip, ports, proto, timeout, workers, banner=False, tick=0.25):
    """Port scan of one host: yields (port, (state, rtt, extra)) or None."""
    if proto == "tcp":
        work = lambda p: scan_tcp(ip, p, timeout, banner)
    else:
        work = lambda p: scan_udp(ip, p, timeout)
    return run_parallel(ports, work, workers, tick)


# --------------------------------------------------------------------------
# output helpers
# --------------------------------------------------------------------------

def paint(text, state, color):
    if color and state in STATE_COLORS:
        return "\033[%sm%s\033[0m" % (STATE_COLORS[state], text)
    return text


def fmt_line(port, proto, state, rtt, extra, color=False):
    st = "%-13s" % state if (rtt is not None or extra) else state
    line = "%5d/%s  %s" % (port, proto, paint(st, state, color))
    if rtt is not None:
        line += "  %6.1f ms" % rtt
    if extra:
        line += "  %s" % extra
    return line


def fmt_counts(counts, order=STATE_ORDER):
    return ", ".join("%s %d" % (s, counts[s])
                     for s in order if counts.get(s)) or "-"


def status_text(done, total, counts, t0, order=STATE_ORDER, width=20):
    fill = width * done // total if total else width
    txt = "[%s%s] %d/%d %3d%% | %s | %.1fs" % (
        "#" * fill, "." * (width - fill), done, total,
        100 * done // total if total else 100, fmt_counts(counts, order),
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
        hosts = proc_arp()
    return sorted(hosts.values(), key=lambda h: _ip_key(h[0]))


def proc_arp():
    """Kernel ARP table from /proc/net/arp: {ip: (ip, mac, dev, '')}."""
    hosts = {}
    try:
        with open("/proc/net/arp") as f:
            next(f, None)                     # header line
            for line in f:
                tok = line.split()
                # IP, HW type, Flags, HW address, Mask, Device
                if (len(tok) >= 6 and tok[2] != "0x0"
                        and tok[3] != "00:00:00:00:00:00"):
                    hosts[tok[0]] = (tok[0], tok[3].lower(), tok[5], "")
    except OSError:
        pass
    return hosts


def local_networks():
    """IPv4 networks directly connected to this system, as a list of
    (dev, own_ip, network). Uses `ip -o -4 addr`, falls back to the
    connected routes in /proc/net/route (own IP unknown there)."""
    nets = []
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             universal_newlines=True, timeout=5).stdout
        for line in out.splitlines():
            tok = line.split()
            if len(tok) < 4 or "inet" not in tok:
                continue
            dev = tok[1].split("@")[0]
            try:
                iface = ipaddress.ip_interface(tok[tok.index("inet") + 1])
            except (ValueError, IndexError):
                continue
            nets.append((dev, str(iface.ip), iface.network))
    except (OSError, subprocess.SubprocessError):
        pass
    if not nets:
        try:
            with open("/proc/net/route") as f:
                next(f, None)
                for line in f:
                    tok = line.split()
                    # Iface Destination Gateway Flags ... Mask (little-endian hex)
                    if len(tok) < 8 or tok[1] == "00000000" or tok[2] != "00000000":
                        continue
                    addr = socket.inet_ntoa(struct.pack("<L", int(tok[1], 16)))
                    mask = socket.inet_ntoa(struct.pack("<L", int(tok[7], 16)))
                    nets.append((tok[0], "",
                                 ipaddress.ip_network("%s/%s" % (addr, mask),
                                                      strict=False)))
        except (OSError, ValueError):
            pass
    seen, result = set(), []
    for dev, ip, net in nets:
        if net.is_loopback or net.prefixlen >= 32 or net in seen:
            continue
        seen.add(net)
        result.append((dev, ip, net))
    return result


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


def live_run(tasks, work, workers, order, show, fmt, ansi):
    """Run work(task) for every task in parallel and print fmt(task, result)
    as results arrive (only states in `show`; all when None), under a live
    progress line with per-state counters. Ctrl+C stops the run and returns
    what was collected so far. Returns (results, counts, elapsed)."""
    total = len(tasks)
    results, counts = {}, {}
    done, last, shown, aborted = 0, 0.0, False, False
    t0 = time.time()
    it = run_parallel(tasks, work, workers)
    try:
        for item in it:
            printed = False
            if item is not None:
                task, res = item
                results[task] = res
                done += 1
                counts[res[0]] = counts.get(res[0], 0) + 1
                if show is None or res[0] in show:
                    if shown:
                        sys.stdout.write("\r\033[K")
                    print(fmt(task, res))
                    printed = True
            now = time.time()
            if ansi and (printed or done == total or now - last >= 0.1):
                sys.stdout.write("\r\033[K"
                                 + status_text(done, total, counts, t0, order))
                sys.stdout.flush()
                shown, last = True, now
    except KeyboardInterrupt:
        aborted = True
    finally:
        it.close()
    if shown:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
    if aborted:
        print("# aborted after %d/%d" % (done, total))
    return results, counts, time.time() - t0


def live_scan(ip, label, ports, proto, opts, ansi, color):
    """Port scan of one host with live output. Ctrl+C stops the scan."""
    total = len(ports)
    show_all = total <= LIVE_ALL_MAX
    print("# target %s | %s | %d port(s) | timeout %.1fs | Ctrl+C stops the scan"
          % (label, proto.upper(), total, opts.timeout))
    if not show_all:
        print("# more than %d ports: only open ports are listed live, "
              "every state is counted" % LIVE_ALL_MAX)
    if proto == "tcp":
        work = lambda p: scan_tcp(ip, p, opts.timeout, opts.banner)
    else:
        work = lambda p: scan_udp(ip, p, opts.timeout)
    res, counts, el = live_run(
        ports, work, opts.workers, STATE_ORDER,
        None if show_all else ("open",),
        lambda p, r: fmt_line(p, proto, r[0], r[1], r[2], color), ansi)
    print("# %d/%d scanned | %s | %.2fs"
          % (len(res), total, fmt_counts(counts), el))
    opened = sorted(p for p, r in res.items() if r[0] == "open")
    if opened and not show_all:
        print("# open: %s" % ",".join(str(p) for p in opened))


def ask_ports(st, key):
    """Prompt for a port spec (default: last one used), returns the list."""
    while True:
        spec = input("Ports [%s]: " % st[key]).strip() or st[key]
        try:
            ports = parse_ports(spec)
        except ValueError:
            ports = []
        if ports:
            st[key] = spec
            return ports
        print("  invalid ports (examples: 502 | 80,443 | 1-1024)")


def scan_loop(target, opts, st, ansi, color):
    ip, label = target
    while True:
        print()
        print("Target: %s" % label)
        ports = ask_ports(st, "ports")
        k = getkey("Protocol [t]cp / [u]dp (Enter = %s): " % st["proto"]).lower()
        if k in ("t", "u"):
            st["proto"] = "tcp" if k == "t" else "udp"
        live_scan(ip, label, ports, st["proto"], opts, ansi, color)
        print()
        k = getkey("[Enter] new scan on this host   [b] back to the menu   "
                   "(Ctrl+C exit): ").lower()
        if k in ("b", "l"):
            return


# -- checks on all hosts of a network --------------------------------------

def host_count(net):
    return net.num_addresses - (2 if net.prefixlen < 31 else 0)


def net_targets(net, own_ip):
    return [str(h) for h in net.hosts() if str(h) != own_ip]


def confirm_big(probes, opts):
    """Ask before a long run: more than CONFIRM_ABOVE probes."""
    if probes <= CONFIRM_ABOVE:
        return True
    worst = -(-probes // max(1, opts.workers)) * opts.timeout
    return getkey("%d probes (worst case ~%ds), continue? [y/N]: "
                  % (probes, worst)).lower() == "y"


def mac_of(ip):
    return proc_arp().get(ip, ("", ""))[1]


def pick_network():
    """Choose a directly connected network, or type one in CIDR notation.
    Returns (network, own_ip) or None."""
    while True:
        nets = local_networks()
        print()
        if nets:
            print("  %3s  %-12s  %-18s  %s" % ("#", "IFACE", "NETWORK", "HOSTS"))
            for i, (dev, ip, net) in enumerate(nets, 1):
                print("  %3d  %-12s  %-18s  %-6d%s"
                      % (i, dev, net, host_count(net),
                         "  this host: %s" % ip if ip else ""))
            hint = ("Select network [1-%d], c=custom CIDR, Enter=back: "
                    % len(nets))
        else:
            print("  No directly connected IPv4 network found.")
            hint = "c=custom CIDR, Enter=back: "
        s = input(hint).strip().lower()
        if not s:
            return None
        if s == "c":
            try:
                net = ipaddress.ip_network(
                    input("Network (e.g. 192.168.55.0/24): ").strip(),
                    strict=False)
            except ValueError:
                print("  invalid network")
                continue
            own = ""
        elif s.isdigit() and 1 <= int(s) <= len(nets):
            _, own, net = nets[int(s) - 1]
        else:
            print("  invalid choice")
            continue
        if net.version != 4:
            print("  only IPv4 networks are supported")
        elif net.prefixlen < MIN_PREFIX:
            print("  %s is too large (maximum /%d)" % (net, MIN_PREFIX))
        else:
            return net, own


def ping_all(net, own, opts, ansi, color):
    """Ping every address of `net`; returns rows for pick_result(),
    None if cancelled."""
    base = ping_cmd()
    if base is None:
        print("  the ping command is not available on this system")
        return None
    targets = net_targets(net, own)
    if not targets:
        return []
    if not confirm_big(len(targets), opts):
        return None
    wait = max(1, int(round(opts.timeout)))
    print("# ping %s | %d address(es) | timeout %ds | Ctrl+C stops"
          % (net, len(targets), wait))

    def fmt(ip, r):
        mac = mac_of(ip)
        return ("  %-15s  %s  %6.1f ms  %s" % (
            ip, paint("alive", "alive", color), r[1],
            "(%s)" % mac if mac else "")).rstrip()

    res, counts, el = live_run(targets, lambda ip: ping_host(ip, wait, base),
                               opts.workers, PING_ORDER, ("alive",), fmt, ansi)
    print("# %d/%d pinged | %s | %.2fs"
          % (len(res), len(targets), fmt_counts(counts, PING_ORDER), el))
    # hosts that resolved ARP but did not answer ping (ICMP blocked)
    neigh = {h[0]: h for h in arp_hosts()
             if ipaddress.ip_address(h[0]) in net}
    alive = {ip for ip, r in res.items() if r[0] == "alive"}
    rows = []
    for ip in sorted(alive | set(neigh), key=_ip_key):
        mac = neigh[ip][1] if ip in neigh else mac_of(ip)
        if ip in alive:
            rows.append((ip, mac, "alive", "%.1f ms" % res[ip][1]))
        elif ip in res:
            rows.append((ip, mac, "arp-only", "no ping reply, ARP %s"
                         % (neigh[ip][3] or "entry present")))
        else:
            rows.append((ip, mac, "arp-only", "not pinged, ARP %s"
                         % (neigh[ip][3] or "entry present")))
    arp_only = sum(1 for r in rows if r[2] == "arp-only")
    if arp_only:
        print("# %d more host(s) in the ARP table without a ping reply "
              "(ICMP blocked?)" % arp_only)
    return rows


def _ports_text(ports):
    ports = sorted(ports)
    return ",".join(map(str, ports)) if len(ports) <= 10 else "%d ports" % len(ports)


def tcp_all(net, own, opts, ansi, color, st):
    """TCP connect to the chosen port(s) on every address of `net`;
    returns rows for pick_result(), None if cancelled."""
    targets = net_targets(net, own)
    if not targets:
        return []
    ports = ask_ports(st, "net_ports")
    tasks = [(ip, p) for ip in targets for p in ports]
    if not confirm_big(len(tasks), opts):
        return None
    live = ("open", "closed") if len(ports) <= 3 else ("open",)
    print("# TCP %s on %s | %d address(es), %d probe(s) | timeout %.1fs | "
          "Ctrl+C stops" % (st["net_ports"], net, len(targets), len(tasks),
                           opts.timeout))
    print("# listed live: %s (closed = host up, port refused); filtered "
          "and error are only counted" % " and ".join(live))

    def fmt(t, r):
        mac = mac_of(t[0])
        return "  %-15s %s%s" % (t[0], fmt_line(t[1], "tcp", r[0], r[1], r[2],
                                                color),
                                 "  (%s)" % mac if mac else "")

    res, counts, el = live_run(
        tasks, lambda t: scan_tcp(t[0], t[1], opts.timeout, opts.banner),
        opts.workers, STATE_ORDER, live, fmt, ansi)
    per_host = {}
    for (ip, p), r in res.items():
        per_host.setdefault(ip, {}).setdefault(r[0], []).append(p)
    neigh = {h[0]: h[1] for h in arp_hosts()}
    rows = []
    for ip in sorted(per_host, key=_ip_key):
        s = per_host[ip]
        if "open" not in s and "closed" not in s:
            continue                          # no answer at all
        parts = ["%s %s" % (k, _ports_text(s[k]))
                 for k in ("open", "closed") if k in s]
        rows.append((ip, neigh.get(ip) or mac_of(ip),
                     "open" if "open" in s else "closed", "; ".join(parts)))
    print("# %d/%d probes | %s | %.2fs"
          % (len(res), len(tasks), fmt_counts(counts), el))
    print("# %d host(s) with open port(s), %d up with the port(s) closed"
          % (sum(1 for r in rows if r[2] == "open"),
             sum(1 for r in rows if r[2] == "closed")))
    return rows


def pick_result(rows, color):
    """Show the hosts found by a check and let the user port-scan one.
    rows=None means the check was cancelled."""
    if rows is None:
        return None
    if not rows:
        print("  no hosts found")
        return None
    print()
    print("  %3s  %-15s  %-19s  %-9s  %s"
          % ("#", "IP", "(MAC)", "RESULT", "DETAILS"))
    for i, (ip, mac, state, info) in enumerate(rows, 1):
        print("  %3d  %-15s  %-19s  %s  %s"
              % (i, ip, "(%s)" % mac if mac else "",
                 paint("%-9s" % state, state, color), info))
    while True:
        s = input("Port-scan a host [1-%d], Enter=back: " % len(rows)).strip()
        if not s:
            return None
        if s.isdigit() and 1 <= int(s) <= len(rows):
            ip, mac = rows[int(s) - 1][:2]
            return ip, ("%s (%s)" % (ip, mac) if mac else ip)
        print("  invalid choice")


MAIN_MENU = """\
  [Enter] hosts in the ARP table: pick one and scan its ports
  [p]     ping all hosts of a network
  [t]     TCP port(s) of your choice on all hosts of a network
  [m]     type a host and scan its ports
  Ctrl+C  exit"""


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
    st = {"ports": DEFAULT_PORTS, "net_ports": DEFAULT_NET_PORTS,
          "proto": opts.proto}
    try:
        while True:
            print()
            print(MAIN_MENU)
            k = getkey("> ").lower()
            if k in ("p", "t"):
                choice = pick_network()
                if not choice:
                    continue
                net, own = choice
                if k == "p":
                    rows = ping_all(net, own, opts, ansi, color)
                else:
                    rows = tcp_all(net, own, opts, ansi, color, st)
                target = pick_result(rows, color)
            elif k == "m":
                target = manual_host()
            else:
                target = pick_from_arp()
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

interactive mode (-i / --interactive), main menu:
  [Enter] list the directly connected hosts from the ARP table (ip neigh,
          or /proc/net/arp) as IP (MAC), pick one, choose ports and
          protocol; results appear live with a progress line
  [p]     ping every address of a network (a connected one, chosen from
          the gateway interfaces, or any CIDR up to /16); also lists hosts
          that answer ARP but block ping
  [t]     TCP check on every address of a network for the port(s) you
          choose: open = service up, closed = host up but port refused
  [m]     type a host and scan its ports
  After [p] and [t] you can pick one of the hosts found and scan its ports.
  Ctrl+C stops a running scan or check; Ctrl+C at the menu exits.
  The ARP table only lists hosts the gateway talked to recently: [p]
  fills it with every host that answers on the network.

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
