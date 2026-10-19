#!/usr/bin/env python3
#
# nsgscanner - minimal TCP/UDP port scanner
# Copyright (c) 2026 BBerry2020
# SPDX-License-Identifier: MIT
# See the LICENSE file for the full license text.
#
"""
nsgscanner.py - TCP/UDP scanner and network checks for a host or a network.

A tool to support troubleshooting performed from Netskope Smart Gateways
(NSG), formerly Infiot: check from the gateway whether a host:port answers,
refuses the connection, or is silently dropped.

Examples:
  python3 nsgscanner.py 192.168.55.56 502
  python3 nsgscanner.py 192.168.55.56 80,443,502 --proto tcp --banner
  python3 nsgscanner.py 192.168.55.56 1-1024 --proto tcp --timeout 1 --workers 200 --open-only
  python3 nsgscanner.py 192.168.55.56 53 --proto udp
  python3 nsgscanner.py --interactive    # menu: ARP hosts, ping/TCP sweep, live

Note: use it only against hosts you own or are explicitly authorized to test.
UDP scanning is inherently ambiguous (connectionless): with no reply you cannot
tell "open" from "filtered" -> state open|filtered.
"""
import argparse, errno, ipaddress, os, queue, re, select, shutil, socket
import struct, subprocess, sys, time
import concurrent.futures as cf

__version__ = "1.4.0"

DEFAULT_PORTS = "1-1024"      # interactive mode: initial port suggestion
DEFAULT_NET_PORTS = "22,80,443"   # interactive "TCP sweep" suggestion
LIVE_ALL_MAX = 64             # interactive mode: show every result live up to N ports
CONFIRM_ABOVE = 1024          # ask before running more probes than this
MIN_PREFIX = 16               # largest network accepted for sweeps
MENU_REFRESH = 2.0            # seconds between main menu refreshes

STATE_ORDER = ("open", "open|filtered", "closed", "filtered", "error")
PING_ORDER = ("alive", "no reply", "error")

# ANSI colours. Scan data (addresses, states, numbers) is bright/coloured;
# helper text (hints, '#' notes, legends, table headers) is grey.
STATE_COLORS = {"open": "1;32", "alive": "1;32", "open|filtered": "36",
                "closed": "33", "arp-only": "33", "filtered": "35",
                "no reply": "2", "error": "31"}
THEME = {"frame": "34", "title": "1;36", "key": "1;33", "help": "90",
         "prompt": "36", "ip": "1", "mac": "36", "data": "",
         "logo": ("96", "96", "36", "36", "34")}

LOGO = r"""
   ____  _________ _______________ _____  ____  ___  _____
  / __ \/ ___/ __ `/ ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / / / (__  ) /_/ (__  ) /__/ /_/ / / / / / / /  __/ /
/_/ /_/____/\__, /____/\___/\__,_/_/ /_/_/ /_/\___/_/
           /____/""".strip("\n").splitlines()

GLYPHS = {
    True: {"h": "─", "v": "│", "tl": "╭", "tr": "╮",
           "bl": "╰", "br": "╯", "full": "█", "empty": "░",
           "spin": "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏",
           "done": "✓", "arrow": "▸", "dot": "●",
           "cell": {"pending": "░", "alive": "█", "open": "█",
                    "closed": "▓", "open|filtered": "▒",
                    "no reply": "·", "filtered": "·", "error": "x",
                    "self": "@"}},
    False: {"h": "-", "v": "|", "tl": "+", "tr": "+", "bl": "+", "br": "+",
            "full": "#", "empty": ".", "spin": "|/-\\", "done": "*",
            "arrow": ">", "dot": "*",
            "cell": {"pending": ".", "alive": "#", "open": "#", "closed": "+",
                     "open|filtered": "?", "no reply": "-", "filtered": "-",
                     "error": "x", "self": "@"}},
}
CELL_RANK = {"pending": 0, "no reply": 1, "filtered": 1, "error": 2,
             "open|filtered": 3, "closed": 3, "alive": 4, "open": 4}
ANSI_RE = re.compile(r"\033\[[0-9;?]*[A-Za-z]")


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
# system information: ARP table, connected networks
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


def mac_of(ip):
    return proc_arp().get(ip, ("", ""))[1]


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


# --------------------------------------------------------------------------
# terminal UI: colours, Unicode/ASCII drawing, keys
# --------------------------------------------------------------------------

def vlen(s):
    """Visible length of a string (ANSI escapes do not count)."""
    return len(ANSI_RE.sub("", s))


def term_size():
    return shutil.get_terminal_size((80, 24))


def vtrunc(s, n):
    """Cut s to n visible characters, keeping ANSI escapes intact."""
    out, vis, i = [], 0, 0
    while i < len(s) and vis < n:
        m = ANSI_RE.match(s, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            continue
        out.append(s[i])
        vis += 1
        i += 1
    if "\033[" in s:
        out.append("\033[0m")
    return "".join(out)


class UI(object):
    """Output styling. Without a terminal (pipe, file) everything is plain
    text, so the one-shot CLI output stays script-friendly."""

    def __init__(self, ansi=False, color=False, uni=False):
        self.ansi, self.color, self.uni = ansi, color, uni
        self.g = GLYPHS[uni]
        self.readline = False
        self._spin = 0

    @classmethod
    def detect(cls, force_ascii=False):
        ansi = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
        color = ansi and "NO_COLOR" not in os.environ
        enc = (getattr(sys.stdout, "encoding", None) or "").lower()
        uni = (ansi and enc.replace("-", "") == "utf8" and not force_ascii
               and not os.environ.get("NSG_ASCII"))
        return cls(ansi, color, uni)

    # -- styling ---------------------------------------------------------
    def c(self, text, code):
        if self.color and code:
            return "\033[%sm%s\033[0m" % (code, text)
        return text

    def t(self, text, role):
        return self.c(text, THEME[role])

    def st(self, text, state):
        return self.c(text, STATE_COLORS.get(state))

    def style(self, text, style):
        if style in THEME:
            return self.t(text, style)
        return self.st(text, style)

    def help(self, text):
        return self.t(text, "help")

    def info(self, text):
        print(self.help("# " + text))

    # -- prompts ---------------------------------------------------------
    def prompt(self, question, hint=""):
        p = self.t(question, "prompt")
        if hint:
            p += " " + self.help("(%s)" % hint)
        return p + self.t(": ", "prompt")

    def ask(self, question, hint=""):
        p = self.prompt(question, hint)
        if self.readline:                     # let readline measure the prompt
            p = ANSI_RE.sub(lambda m: "\001" + m.group(0) + "\002", p)
        return input(p).strip()

    def key(self, question, hint=""):
        return getkey(self.prompt(question, hint)).lower()

    def pause(self):
        getkey(self.help("press any key to continue "))

    # -- screen ----------------------------------------------------------
    def clear(self):
        if self.ansi:
            sys.stdout.write("\033[H\033[2J")
            sys.stdout.flush()

    def cursor(self, show):
        if self.ansi:
            sys.stdout.write("\033[?25h" if show else "\033[?25l")
            sys.stdout.flush()

    def section(self, title):
        """Clear the screen and print a title bar for a new screen."""
        self.clear()
        g = self.g
        width = min(term_size().columns, 80) - 1
        head = (self.t(" nsgscanner ", "title") + self.help(g["arrow"]) + " "
                + self.t(title, "ip") + " ")
        print(self.t(g["h"] * 2, "frame") + head
              + self.t(g["h"] * max(2, width - 2 - vlen(head)), "frame"))
        print()

    def box(self, title, lines, right="", width=0):
        """Frame lines in a box with a title (and an optional right label)."""
        g = self.g
        fr = lambda s: self.t(s, "frame")
        inner = max([vlen(l) for l in lines] +
                    [vlen(title) + vlen(right) + 8, width - 4])
        inner = min(inner, term_size().columns - 7)    # never wrap the frame
        cut = "…" if self.uni else "~"
        lines = [l if vlen(l) <= inner else vtrunc(l, inner - 1) + self.help(cut)
                 for l in lines]
        total = inner + 4
        fill = total - 5 - vlen(title) - (vlen(right) + 3 if right else 0)
        top = fr(g["tl"] + g["h"]) + " " + self.t(title, "title") + " "
        top += fr(g["h"] * max(1, fill))
        if right:
            top += " " + self.help(right) + " " + fr(g["h"])
        out = [top + fr(g["tr"])]
        for l in lines:
            out.append(fr(g["v"]) + " " + l + " " * (inner - vlen(l)) + " "
                       + fr(g["v"]))
        out.append(fr(g["bl"] + g["h"] * (total - 2) + g["br"]))
        return out

    def table(self, headers, rows):
        """rows: lists of (text, style) cells. ANSI-safe column alignment."""
        widths = [len(h) for h in headers]
        for r in rows:
            for i, (txt, _) in enumerate(r):
                widths[i] = max(widths[i], len(txt))
        out = [self.help("  ".join(h.ljust(widths[i])
                                   for i, h in enumerate(headers)).rstrip())]
        for r in rows:
            cells = [self.style(txt.ljust(widths[i]) if i < len(r) - 1 else txt,
                                style) for i, (txt, style) in enumerate(r)]
            out.append("  ".join(cells))
        return out

    # -- progress --------------------------------------------------------
    def spinner(self):
        s = self.g["spin"]
        self._spin += 1
        return s[self._spin % len(s)]

    def bar(self, done, total, width=20):
        fill = width * done // total if total else width
        return (self.c(self.g["full"] * fill, "32")
                + self.help(self.g["empty"] * (width - fill)))

    def status(self, done, total, counts, t0, order=STATE_ORDER):
        pct = 100 * done // total if total else 100
        mark = self.g["done"] if done >= total else self.spinner()
        cnt = [(s, counts[s]) for s in order if counts.get(s)]
        txt = "%s %s %s %s %s %s %s" % (
            self.t(mark, "title"), self.bar(done, total),
            self.t("%d/%d" % (done, total), "ip"), self.help("%3d%%" % pct),
            self.help("|"),
            ", ".join(self.st("%s %d" % sc, sc[0]) for sc in cnt)
            or self.help("-"),
            self.help("| %.1fs" % (time.time() - t0)))
        cols = term_size().columns
        if vlen(txt) >= cols:                 # never wrap: \r redraw would break
            txt = ANSI_RE.sub("", txt)[:max(10, cols - 1)]
        return txt


PLAIN = UI()


def getkey(prompt="", timeout=None):
    """Read a single keypress (cbreak mode keeps Ctrl+C working). Returns
    '' for Enter/space, None when `timeout` expires with no key. Falls back
    to line input without a terminal."""
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
        if timeout is not None and not select.select([fd], [], [], timeout)[0]:
            return None
        data = os.read(fd, 32)                # swallow escape sequences whole
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    if not data or data[:1] == b"\x04":       # EOF / Ctrl+D
        raise EOFError
    ch = data[:1].decode("latin-1")
    print(ch if ch.isprintable() else "")
    return ch.strip()


class NoEcho(object):
    """Turn terminal echo off during a live view (typed keys or ^C would
    land in the middle of it) and drop anything typed meanwhile."""

    def __enter__(self):
        self.old = None
        try:
            import termios
            self.termios, self.fd = termios, sys.stdin.fileno()
            self.old = termios.tcgetattr(self.fd)
            new = termios.tcgetattr(self.fd)
            new[3] &= ~termios.ECHO
            termios.tcsetattr(self.fd, termios.TCSADRAIN, new)
        except Exception:
            self.old = None
        return self

    def __exit__(self, *exc):
        if self.old is not None:
            try:
                self.termios.tcflush(self.fd, self.termios.TCIFLUSH)
                self.termios.tcsetattr(self.fd, self.termios.TCSADRAIN, self.old)
            except Exception:
                pass
        return False


# --------------------------------------------------------------------------
# live views
# --------------------------------------------------------------------------

def fmt_line(port, proto, state, rtt, extra, ui=PLAIN):
    st = "%-13s" % state if (rtt is not None or extra) else state
    line = ui.t("%5d/%s" % (port, proto), "ip") + "  " + ui.st(st, state)
    if rtt is not None:
        line += "  " + ui.t("%6.1f ms" % rtt, "data")
    if extra:
        line += "  " + ui.t(extra, "data")
    return line


def fmt_counts(counts, order=STATE_ORDER):
    return ", ".join("%s %d" % (s, counts[s])
                     for s in order if counts.get(s)) or "-"


class ScrollView(object):
    """Results printed as lines as they arrive, under a status line."""

    def __init__(self, ui, show, fmt, order):
        self.ui, self.show, self.fmt, self.order = ui, show, fmt, order
        self.drawn = False

    def open(self):
        self.ui.cursor(False)

    def result(self, task, res):
        if self.show is None or res[0] in self.show:
            self._clear()
            print(self.fmt(task, res))
            return True                       # redraw the status line now
        return False

    def draw(self, done, total, counts, t0):
        if self.ui.ansi:
            sys.stdout.write("\r\033[K" + self.ui.status(done, total, counts,
                                                         t0, self.order))
            sys.stdout.flush()
            self.drawn = True

    def finish(self, done, total, counts, t0):
        self._clear()

    def close(self):
        self.ui.cursor(True)

    def _clear(self):
        if self.drawn:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
            self.drawn = False


class GridView(object):
    """Live map of a network, one cell per address, redrawn in place:
    cells change as replies arrive, with a progress line, a legend and the
    latest hosts found."""
    RECENT = 4

    def __init__(self, ui, title, right, net, own, ip_of, order, legend,
                 found, fmt_found):
        self.ui, self.title, self.right, self.net = ui, title, right, net
        self.ip_of, self.order = ip_of, order
        self.legend = [l for l in legend if own or l[0] != "self"]
        self.found, self.fmt_found = found, fmt_found
        self.base = int(net.network_address)
        self.n = net.num_addresses
        self.cols = self._cols()
        self.rows = -(-self.n // self.cols)
        self.cell = {int(h) - self.base: "pending" for h in net.hosts()}
        if own:
            self.cell[int(ipaddress.ip_address(own)) - self.base] = "self"
        self.recent = []
        self.height = 0

    @staticmethod
    def _cols():
        return 32 if term_size().columns >= 80 else 16

    @classmethod
    def fits(cls, net):
        size = term_size()
        cols = cls._cols()
        rows = -(-net.num_addresses // cols)
        return (net.num_addresses <= 1024 and size.columns >= cols * 2 + 14
                and rows + 7 + cls.RECENT <= size.lines - 1)

    def glyph(self, state):
        ch = self.ui.g["cell"].get(state, " ")
        if state == "pending":
            return self.ui.help(ch)
        if state == "self":
            return self.ui.t(ch, "title")
        return self.ui.st(ch, state)

    def open(self):
        self.ui.cursor(False)

    def result(self, task, res):
        ip = self.ip_of(task)
        off = int(ipaddress.ip_address(ip)) - self.base
        cur = self.cell.get(off, "pending")
        if cur == "pending" or CELL_RANK.get(res[0], 0) > CELL_RANK.get(cur, 0):
            self.cell[off] = res[0]
        if res[0] in self.found:
            self.recent.append(self.fmt_found(task, res))
        return False

    def render(self, done, total, counts, t0):
        ui = self.ui
        ruler = [" "] * (self.cols * 2)
        for c in range(0, min(self.cols, self.n), 8):
            ruler[c * 2:c * 2 + len(str(c))] = list(str(c))
        lines = [ui.help(" " * 8 + "".join(ruler).rstrip())]
        for r in range(self.rows):
            first = self.base + r * self.cols
            if self.net.prefixlen >= 24:
                label = ".%d" % (first & 255)
            else:
                label = "%d.%d" % ((first >> 8) & 255, first & 255)
            offs = range(r * self.cols, min((r + 1) * self.cols, self.n))
            cells = " ".join(self.glyph(self.cell[o]) if o in self.cell
                             else " " for o in offs)
            lines.append(ui.help(label.rjust(7)) + " " + cells)
        out = ui.box(self.title, lines, self.right)
        out.append(" " + ui.status(done, total, counts, t0, self.order))
        out.append(" " + "  ".join(self.glyph(s) + " " + ui.help(lbl)
                                   for s, lbl in self.legend))
        latest = self.recent[::-1][:self.RECENT]
        for i in range(self.RECENT):
            head = ui.help("latest " if i == 0 else "       ")
            out.append(" " + head + (latest[i] if i < len(latest)
                                     else (ui.help("-") if i == 0 else "")))
        return out

    def draw(self, done, total, counts, t0):
        lines = self.render(done, total, counts, t0)
        buf = ["\033[%dA\r" % self.height] if self.height else []
        buf += [l + "\033[K\n" for l in lines]
        sys.stdout.write("".join(buf))
        sys.stdout.flush()
        self.height = len(lines)

    def finish(self, done, total, counts, t0):
        self.draw(done, total, counts, t0)

    def close(self):
        self.ui.cursor(True)


def live_run(ui, tasks, work, workers, view):
    """Run work(task) for every task in parallel, feeding results to a live
    view. Ctrl+C stops the run and keeps what was collected so far.
    Returns (results, counts, elapsed)."""
    total = len(tasks)
    results, counts = {}, {}
    done, last, aborted = 0, 0.0, False
    t0 = time.time()
    with NoEcho() if ui.ansi else _null():
        it = run_parallel(tasks, work, workers)
        view.open()
        try:
            for item in it:
                urgent = False
                if item is not None:
                    task, res = item
                    results[task] = res
                    done += 1
                    counts[res[0]] = counts.get(res[0], 0) + 1
                    urgent = view.result(task, res)
                now = time.time()
                if urgent or done == total or now - last >= 0.1:
                    view.draw(done, total, counts, t0)
                    last = now
        except KeyboardInterrupt:
            aborted = True
        finally:
            it.close()
            view.finish(done, total, counts, t0)
            view.close()
    if aborted:
        ui.info("aborted after %d/%d" % (done, total))
    return results, counts, time.time() - t0


class _null(object):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# --------------------------------------------------------------------------
# interactive mode: screens
# --------------------------------------------------------------------------

MENU_ITEMS = (("Enter", "ARP hosts", "pick a neighbour and scan its ports"),
              ("p", "ping sweep", "ping every address of a network"),
              ("t", "TCP sweep", "port(s) of your choice on every address"),
              ("m", "manual host", "type a host and scan its ports"))


def menu_screen(ui, opts):
    """Main menu lines: logo, live gateway dashboard, menu entries."""
    out = [""]
    for i, l in enumerate(LOGO):
        out.append("  " + ui.c(l, THEME["logo"][i % len(THEME["logo"])]))
    out.append("  " + ui.help("NSG troubleshooting toolkit") + "  "
               + ui.t("v" + __version__, "title") + "  "
               + ui.help("Netskope Smart Gateway (ex Infiot)"))
    out.append("")
    nets = local_networks()
    shown = ["%s %s" % (ui.help(dev), ui.t("%s/%d" % (ip, net.prefixlen) if ip
                                           else str(net), "ip"))
             for dev, ip, net in nets[:4]]
    if len(nets) > 4:
        shown.append(ui.help("+%d more" % (len(nets) - 4)))
    neigh = arp_hosts()
    rows = ["   ".join(shown) or ui.help("no IPv4 network found"),
            "%s %s   %s %s   %s %s   %s %s" % (
                ui.help("ARP neighbours"), ui.t(str(len(neigh)), "ip"),
                ui.help("timeout"), ui.t("%.1fs" % opts.timeout, "data"),
                ui.help("workers"), ui.t(str(opts.workers), "data"),
                ui.help("banner"), ui.t("on" if opts.banner else "off", "data"))]
    for l in ui.box(socket.gethostname(), rows, time.strftime("%H:%M:%S"),
                    width=66):
        out.append("  " + l)
    out.append("")
    for k, label, desc in MENU_ITEMS:
        out.append("   %s %s %s" % (ui.t(("[%s]" % k).ljust(8), "key"),
                                    ui.t(label.ljust(12), "ip"), ui.help(desc)))
    out.append("   %s %s" % (ui.t("Ctrl+C".ljust(8), "key"), ui.help("exit")))
    out.append("")
    return out


def menu_choice(ui, opts):
    """Show the main menu and return the key pressed. On a terminal the
    dashboard refreshes every MENU_REFRESH seconds until a key arrives."""
    if not ui.ansi:
        for l in menu_screen(ui, opts):
            print(l)
        return getkey("> ").lower()
    ui.clear()
    while True:
        lines = menu_screen(ui, opts)
        sys.stdout.write("\033[H" + "".join(l + "\033[K\n" for l in lines)
                         + "\033[J" + ui.t(" > ", "prompt"))
        sys.stdout.flush()
        k = getkey(timeout=MENU_REFRESH)
        if k is not None:
            return k.lower()


def manual_host(ui):
    while True:
        h = ui.ask("Host", "IP or name, Enter back")
        if not h:
            return None
        try:
            ip = socket.gethostbyname(h)
        except (socket.gaierror, UnicodeError) as e:
            print(ui.st("  name resolution failed: %s" % e, "error"))
            continue
        return ip, (ip if h == ip else "%s (%s)" % (h, ip))


def _arp_state_style(s):
    return {"REACHABLE": "alive", "PERMANENT": "alive",
            "STALE": "closed", "DELAY": "closed", "PROBE": "closed"}.get(s, "help")


def pick_from_arp(ui):
    ui.section("ARP hosts")
    while True:
        hosts = arp_hosts()
        if hosts:
            rows = [[("%d" % i, "key"), (ip, "ip"), ("(%s)" % mac, "mac"),
                     (dev, "data"), (st or "-", _arp_state_style(st))]
                    for i, (ip, mac, dev, st) in enumerate(hosts, 1)]
            body = ui.table(["#", "IP", "MAC", "IFACE", "STATE"], rows)
        else:
            body = [ui.help("ARP table is empty: only hosts this gateway "
                            "talked to recently are listed."),
                    ui.help("Use the ping sweep [p] from the menu to fill it.")]
        for l in ui.box("ARP neighbours (%d)" % len(hosts), body,
                        time.strftime("%H:%M:%S")):
            print(" " + l)
        hint = ("1-%d, " % len(hosts) if hosts else "") + "r refresh, m manual, Enter back"
        s = ui.ask("Select host", hint).lower()
        if not s:
            return None
        if s == "r":
            ui.section("ARP hosts")
            continue
        if s == "m":
            target = manual_host(ui)
            if target:
                return target
            continue
        if s.isdigit() and 1 <= int(s) <= len(hosts):
            ip, mac = hosts[int(s) - 1][:2]
            return ip, "%s (%s)" % (ip, mac)
        print(ui.st("  invalid choice", "error"))


def live_scan(ui, ip, label, ports, proto, opts):
    """Port scan of one host with live output. Ctrl+C stops the scan."""
    total = len(ports)
    show_all = total <= LIVE_ALL_MAX
    ui.info("target %s | %s | %d port(s) | timeout %.1fs | Ctrl+C stops the scan"
            % (label, proto.upper(), total, opts.timeout))
    if not show_all:
        ui.info("more than %d ports: only open ports are listed live, every "
                "state is counted" % LIVE_ALL_MAX)
    if proto == "tcp":
        work = lambda p: scan_tcp(ip, p, opts.timeout, opts.banner)
    else:
        work = lambda p: scan_udp(ip, p, opts.timeout)
    view = ScrollView(ui, None if show_all else ("open",),
                      lambda p, r: fmt_line(p, proto, r[0], r[1], r[2], ui),
                      STATE_ORDER)
    res, counts, el = live_run(ui, ports, work, opts.workers, view)
    print(ui.help("# %d/%d scanned | " % (len(res), total))
          + ", ".join(ui.st("%s %d" % (s, counts[s]), s)
                      for s in STATE_ORDER if counts.get(s))
          + ui.help(" | %.2fs" % el))
    opened = sorted(p for p, r in res.items() if r[0] == "open")
    if opened and not show_all:
        print(ui.help("# open: ") + ui.st(",".join(map(str, opened)), "open"))


def ask_ports(ui, st, key):
    """Prompt for a port spec (default: last one used), returns the list."""
    while True:
        spec = ui.ask("Ports", "Enter = %s" % st[key]) or st[key]
        try:
            ports = parse_ports(spec)
        except ValueError:
            ports = []
        if ports:
            st[key] = spec
            return ports
        print(ui.st("  invalid ports (examples: 502 | 80,443 | 1-1024)",
                    "error"))


def scan_loop(ui, target, opts, st):
    ip, label = target
    while True:
        ui.section("port scan")
        for l in ui.box("target", [ui.t(label, "ip")]):
            print(" " + l)
        ports = ask_ports(ui, st, "ports")
        k = ui.key("Protocol", "t tcp, u udp, Enter = %s" % st["proto"])
        if k in ("t", "u"):
            st["proto"] = "tcp" if k == "t" else "udp"
        print()
        live_scan(ui, ip, label, ports, st["proto"], opts)
        print()
        k = ui.key("Next", "Enter new scan on this host, b back to the menu")
        if k in ("b", "l"):
            return


# -- sweeps: checks on every address of a network ---------------------------

def host_count(net):
    return net.num_addresses - (2 if net.prefixlen < 31 else 0)


def net_targets(net, own_ip):
    return [str(h) for h in net.hosts() if str(h) != own_ip]


def confirm_big(ui, probes, opts):
    """Ask before a long run: more than CONFIRM_ABOVE probes."""
    if probes <= CONFIRM_ABOVE:
        return True
    worst = -(-probes // max(1, opts.workers)) * opts.timeout
    return ui.key("%d probes, worst case ~%ds. Continue" % (probes, worst),
                  "y/N") == "y"


def pick_network(ui, title):
    """Choose a directly connected network, or type one in CIDR notation.
    Returns (dev, network, own_ip) or None."""
    ui.section(title)
    while True:
        nets = local_networks()
        if nets:
            rows = [[("%d" % i, "key"), (dev, "data"), (str(net), "ip"),
                     ("%d" % host_count(net), "data"), (ip or "-", "help")]
                    for i, (dev, ip, net) in enumerate(nets, 1)]
            body = ui.table(["#", "IFACE", "NETWORK", "HOSTS", "THIS GATEWAY"],
                            rows)
        else:
            body = [ui.help("No directly connected IPv4 network found.")]
        for l in ui.box("Networks", body):
            print(" " + l)
        hint = ("1-%d, " % len(nets) if nets else "") + "c custom CIDR, Enter back"
        s = ui.ask("Select network", hint).lower()
        if not s:
            return None
        dev = ""
        if s == "c":
            try:
                net = ipaddress.ip_network(
                    ui.ask("Network", "e.g. 192.168.55.0/24"), strict=False)
            except ValueError:
                print(ui.st("  invalid network", "error"))
                continue
            own = ""
        elif s.isdigit() and 1 <= int(s) <= len(nets):
            dev, own, net = nets[int(s) - 1]
        else:
            print(ui.st("  invalid choice", "error"))
            continue
        if net.version != 4:
            print(ui.st("  only IPv4 networks are supported", "error"))
        elif net.prefixlen < MIN_PREFIX:
            print(ui.st("  %s is too large (maximum /%d)" % (net, MIN_PREFIX),
                        "error"))
        else:
            return dev, net, own


def _found_line(ui, ip, state, text):
    mac = mac_of(ip)
    return "%s %s %s%s" % (ui.st(ui.g["dot"], state), ui.t(ip.ljust(15), "ip"),
                           text, "  " + ui.t("(%s)" % mac, "mac") if mac else "")


def ping_sweep(ui, dev, net, own, opts):
    """Ping every address of `net`; returns rows for pick_result(),
    None if cancelled."""
    base = ping_cmd()
    if base is None:
        print(ui.st("  the ping command is not available on this system",
                    "error"))
        ui.pause()
        return None
    targets = net_targets(net, own)
    if not targets:
        return []
    if not confirm_big(ui, len(targets), opts):
        return None
    wait = max(1, int(round(opts.timeout)))
    ui.info("ping %s | %d address(es) | timeout %ds | Ctrl+C stops"
            % (net, len(targets), wait))
    if ui.ansi and GridView.fits(net):
        view = GridView(ui, "ping %s" % net, dev, net, own, lambda ip: ip,
                        PING_ORDER,
                        [("alive", "alive"), ("no reply", "no reply"),
                         ("pending", "pending"), ("self", "this gateway")],
                        ("alive",),
                        lambda ip, r: _found_line(ui, ip, "alive", ui.t(
                            "%6.1f ms" % r[1], "data")))
    else:
        view = ScrollView(ui, ("alive",), lambda ip, r: "  " + _found_line(
            ui, ip, "alive", ui.t("%6.1f ms" % r[1], "data")), PING_ORDER)
    res, counts, el = live_run(ui, targets,
                               lambda ip: ping_host(ip, wait, base),
                               opts.workers, view)
    ui.info("%d/%d pinged | %s | %.2fs"
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
        else:
            rows.append((ip, mac, "arp-only", "%s, ARP %s" % (
                "no ping reply" if ip in res else "not pinged",
                neigh[ip][3] or "entry present")))
    arp_only = sum(1 for r in rows if r[2] == "arp-only")
    if arp_only:
        ui.info("%d more host(s) in the ARP table without a ping reply "
                "(ICMP blocked?)" % arp_only)
    return rows


def _ports_text(ports):
    ports = sorted(ports)
    return ",".join(map(str, ports)) if len(ports) <= 10 else "%d ports" % len(ports)


def tcp_sweep(ui, dev, net, own, opts, st):
    """TCP connect to the chosen port(s) on every address of `net`;
    returns rows for pick_result(), None if cancelled."""
    targets = net_targets(net, own)
    if not targets:
        return []
    ports = ask_ports(ui, st, "net_ports")
    tasks = [(ip, p) for ip in targets for p in ports]
    if not confirm_big(ui, len(tasks), opts):
        return None
    live = ("open", "closed") if len(ports) <= 3 else ("open",)
    ui.info("TCP %s on %s | %d address(es), %d probe(s) | timeout %.1fs | "
            "Ctrl+C stops" % (st["net_ports"], net, len(targets), len(tasks),
                              opts.timeout))
    fmt_found = lambda t, r: _found_line(
        ui, t[0], r[0], "%s %s" % (ui.t("%5d/tcp" % t[1], "ip"),
                                   ui.st("%-6s" % r[0], r[0])))
    if ui.ansi and GridView.fits(net):
        view = GridView(ui, "TCP %s on %s" % (st["net_ports"], net), dev, net,
                        own, lambda t: t[0], STATE_ORDER,
                        [("open", "open"), ("closed", "closed: host up"),
                         ("filtered", "no answer"), ("pending", "pending"),
                         ("self", "this gateway")],
                        live, fmt_found)
    else:
        ui.info("listed live: %s (closed = host up, port refused); filtered "
                "and error are only counted" % " and ".join(live))
        view = ScrollView(ui, live, lambda t, r: "  " + fmt_found(t, r),
                          STATE_ORDER)
    res, counts, el = live_run(
        ui, tasks, lambda t: scan_tcp(t[0], t[1], opts.timeout, opts.banner),
        opts.workers, view)
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
    ui.info("%d/%d probes | %s | %.2fs"
            % (len(res), len(tasks), fmt_counts(counts), el))
    ui.info("%d host(s) with open port(s), %d up with the port(s) closed"
            % (sum(1 for r in rows if r[2] == "open"),
               sum(1 for r in rows if r[2] == "closed")))
    return rows


def pick_result(ui, rows):
    """Show the hosts found by a sweep and let the user port-scan one.
    rows=None means the sweep was cancelled."""
    if rows is None:
        return None
    if not rows:
        print(ui.help("  no hosts found"))
        ui.pause()
        return None
    print()
    body = ui.table(["#", "IP", "MAC", "RESULT", "DETAILS"],
                    [[("%d" % i, "key"), (ip, "ip"),
                      ("(%s)" % mac if mac else "", "mac"), (state, state),
                      (info, "data")]
                     for i, (ip, mac, state, info) in enumerate(rows, 1)])
    for l in ui.box("Hosts found (%d)" % len(rows), body):
        print(" " + l)
    while True:
        s = ui.ask("Port-scan a host", "1-%d, Enter back to the menu" % len(rows))
        if not s:
            return None
        if s.isdigit() and 1 <= int(s) <= len(rows):
            ip, mac = rows[int(s) - 1][:2]
            return ip, ("%s (%s)" % (ip, mac) if mac else ip)
        print(ui.st("  invalid choice", "error"))


def interactive(opts):
    ui = UI.detect(opts.ascii)
    try:
        __import__("readline")                # line editing for input()
        ui.readline = True
    except ImportError:
        pass
    st = {"ports": DEFAULT_PORTS, "net_ports": DEFAULT_NET_PORTS,
          "proto": opts.proto}
    try:
        while True:
            k = menu_choice(ui, opts)
            if k in ("p", "t"):
                choice = pick_network(ui, "ping sweep" if k == "p"
                                      else "TCP sweep")
                if not choice:
                    continue
                print()
                if k == "p":
                    rows = ping_sweep(ui, choice[0], choice[1], choice[2], opts)
                else:
                    rows = tcp_sweep(ui, choice[0], choice[1], choice[2], opts,
                                     st)
                target = pick_result(ui, rows)
            elif k == "m":
                ui.section("manual host")
                target = manual_host(ui)
            else:
                target = pick_from_arp(ui)
            if target:
                scan_loop(ui, target, opts, st)
    except (KeyboardInterrupt, EOFError):
        ui.cursor(True)
        print("\n" + ui.help("# bye"))
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
  nsgscanner -i [options]               interactive menu with live views"""

HELP_EPILOG = """\
examples:
  nsgscanner 192.168.55.56 502                     single TCP port
  nsgscanner 192.168.55.56 80,443,502 --banner     port list + banner grab
  nsgscanner 192.168.55.56 1-1024 --open-only      port range, open only
  nsgscanner 192.168.55.56 53 --proto udp          UDP
  nsgscanner -i                                    interactive menu
  nsgscanner -i --timeout 1 --banner               interactive, options
                                                   applied to every run

interactive mode (-i / --interactive), main menu:
  The menu shows a dashboard of the gateway (networks, ARP neighbours,
  clock) refreshed every 2 seconds.
  [Enter] list the directly connected hosts from the ARP table (ip neigh,
          or /proc/net/arp) as IP (MAC), pick one, choose ports and
          protocol; results appear live with a progress line
  [p]     ping sweep: ping every address of a network (a connected one,
          chosen from the gateway interfaces, or any CIDR up to /16);
          also lists hosts that answer ARP but block ping
  [t]     TCP sweep: the port(s) you choose on every address of a
          network: open = service up, closed = host up but port refused
  [m]     type a host and scan its ports
  Sweeps on networks up to /22 show a live map, one cell per address.
  After [p] and [t] you can pick one of the hosts found and scan its ports.
  Ctrl+C stops a running scan or sweep; Ctrl+C at the menu exits.

display:
  Colours on a terminal: scan data is bold/coloured (addresses, states,
  times), helper text is grey. Colours are off when the output is not a
  terminal or NO_COLOR is set. Unicode drawing is used on UTF-8 terminals;
  --ascii (or NSG_ASCII=1) forces plain ASCII.

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
                    help="interactive menu: ARP hosts, ping sweep, TCP sweep, "
                         "live views (Ctrl+C to exit)")
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
    ap.add_argument("--ascii", action="store_true",
                    help="plain ASCII drawing, no Unicode box/block characters")
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

    ui = UI.detect(args.ascii)
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

    print(ui.help("# target %s (%s) | %s | %d port(s) | timeout %.1fs"
                  % (args.host, ip, args.proto.upper(), len(ports),
                     args.timeout)))

    t0 = time.time()
    results = {}
    try:
        for item in scan_iter(ip, ports, args.proto, args.timeout,
                              args.workers, args.banner):
            if item is not None:
                results[item[0]] = item[1]
    except KeyboardInterrupt:
        print("\n" + ui.help("# aborted"))
        sys.stdout.flush()
        os._exit(130)       # exit now, don't wait for in-flight probes

    openc = 0
    for p in ports:
        state, rtt, extra = results[p]
        is_open = state.startswith("open")
        openc += is_open
        if args.open_only and not is_open:
            continue
        print(fmt_line(p, args.proto, state, rtt, extra, ui))
    print(ui.help("# %d open (or open|filtered) of %d | %.2fs"
                  % (openc, len(ports), time.time() - t0)))


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:                  # output piped into head & co.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
