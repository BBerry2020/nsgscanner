# nsgscanner

A tiny, dependency-free TCP/UDP port scanner in a single Python file, built to
support troubleshooting performed from **Netskope Smart Gateways (NSG)**,
formerly **Infiot**. Run it from the gateway to check whether a host:port
answers, refuses the connection, or is silently dropped along the path.

Scan one host and one or more ports, pick the protocol, and get clear per-port
states.

> Independent tool, not an official Netskope product.

- **No dependencies** — Python 3.6+ standard library only.
- **No root** — uses `connect()` / `sendto()`, not raw sockets.
- **Parallel** — threaded, tunable with `--workers`.
- **Clear states** — distinguishes `open` / `closed` / `filtered` (and UDP `open|filtered`).
- **Interactive console** — `-i` opens a menu with a live gateway dashboard,
  ping and TCP sweeps drawn as a refreshing map of the network, and colours
  that keep scan data apart from helper text.

> **Authorized use only.** Scan hosts you own or are explicitly permitted to
> test. You are responsible for how you use this tool.

## Install

### Quick (run from the current directory)

```sh
curl -fsSL https://raw.githubusercontent.com/BBerry2020/nsgscanner/main/nsgscanner.py -o nsgscanner.py
chmod +x nsgscanner.py
./nsgscanner.py 192.168.55.56 502
```

### System-wide (run as `nsgscanner` from anywhere)

```sh
sudo curl -fsSL https://raw.githubusercontent.com/BBerry2020/nsgscanner/main/nsgscanner.py -o /usr/local/bin/nsgscanner
sudo chmod +x /usr/local/bin/nsgscanner
nsgscanner 192.168.55.56 502
```

### Clone the repo

```sh
git clone https://github.com/BBerry2020/nsgscanner.git
cd nsgscanner
chmod +x nsgscanner.py
./nsgscanner.py --help
```

## Usage

```sh
nsgscanner <host> <ports> [--proto tcp|udp] [--timeout S] [--workers N] [--banner] [--open-only]
nsgscanner --interactive [--proto tcp|udp] [--timeout S] [--workers N] [--banner]
```

Run `nsgscanner` with no arguments (or `nsgscanner -h`) for the full help:
options, examples, the interactive mode workflow and the port states.

### Examples

```sh
nsgscanner 192.168.55.56 502                        # single TCP port
nsgscanner 192.168.55.56 80,443,502 --banner        # list + banner grab
nsgscanner 192.168.55.56 1-1024 --workers 200 --open-only
nsgscanner 192.168.55.56 53 --proto udp             # UDP
nsgscanner --interactive                            # menu + live scan
```

## Interactive mode

`nsgscanner --interactive` (or `-i`) opens a console with a live dashboard of
the gateway (hostname, connected networks, ARP neighbours, clock, refreshed
every 2 seconds) and a menu of checks:

```text
   [Enter]  ARP hosts    pick a neighbour and scan its ports
   [p]      ping sweep   ping every address of a network
   [t]      TCP sweep    port(s) of your choice on every address
   [m]      manual host  type a host and scan its ports
   Ctrl+C   exit
```

- **`[Enter]` ARP hosts** — lists the neighbours in the ARP table (`ip neigh`,
  or `/proc/net/arp` when the `ip` command is missing) as `IP (MAC)` pairs.
  Pick one, enter ports and protocol, and watch the results live.
- **`[p]` ping sweep** — choose a network directly connected to the gateway
  (read from its interfaces with `ip addr`, or `/proc/net/route`) or type any
  CIDR up to `/16`, then every address is pinged with the system `ping`
  command. Hosts that answer ARP but block ICMP are listed as `arp-only`.
- **`[t]` TCP sweep** — same network choice, then the port(s) you pick are
  checked on every address: `open` means the service is up, `closed` means
  the host is up but refuses the port; addresses with no answer are only
  counted.
- **`[m]`** — type a host and scan its ports.

Sweeps on networks up to `/22` are drawn as a **live map**, one cell per
address, redrawn in place as replies arrive, with a progress line, a legend
and the latest hosts found. After `[p]` and `[t]` the hosts found are listed
and you can pick one to scan its ports. Runs above 1024 probes ask for
confirmation first.

`Ctrl+C` during a scan or sweep stops it and returns to the menu; `Ctrl+C` at
the menu exits. `--timeout`, `--workers` and `--banner` apply to every run.

```text
# ping 192.168.55.0/24 | 253 address(es) | timeout 1s | Ctrl+C stops
╭─ ping 192.168.55.0/24 ────────────────────────────────────────── VLAN1 ─╮
│         0               8               16              24              │
│      .0   █ · · · · · · · · · · █ █ · · · · · · · · · · · · · · · · · · │
│     .32 · · · · · · · · · · · · · · · · · · · · · · · · █ · · · · · · · │
│     .64 · · · · · · · · · · · · · █ · · · · · · · · · · · · · · · · · · │
│     .96 · · · · · █ · · · · · · · · · · · · · · · · · · · · · · · · · · │
│    .128 · · · · · · · · · · · · · · · · · · · · · · █ · · · · · · · · · │
│    .160 · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · │
│    .192 · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · │
│    .224 · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · @   │
╰─────────────────────────────────────────────────────────────────────────╯
 ✓ ████████████████████ 253/253 100% | alive 7, no reply 246 | 4.7s
 █ alive  · no reply  ░ pending  @ this gateway
 latest ● 192.168.55.150     0.4 ms
        ● 192.168.55.77      0.5 ms
        ● 192.168.55.13      0.4 ms
        ● 192.168.55.101     0.4 ms
# 253/253 pinged | alive 7, no reply 246 | 4.66s
# 1 more host(s) in the ARP table without a ping reply (ICMP blocked?)

 ╭─ Hosts found (8) ──────────────────────────────────────────────────────────────╮
 │ #  IP              MAC                  RESULT    DETAILS                      │
 │ 1  192.168.55.1    (3c:22:fb:11:22:33)  alive     0.4 ms                       │
 │ 2  192.168.55.12                        alive     0.4 ms                       │
 │ 3  192.168.55.13                        alive     0.4 ms                       │
 │ 4  192.168.55.56   (c0:cd:d6:c3:56:dc)  alive     0.5 ms                       │
 │ 5  192.168.55.77                        alive     0.5 ms                       │
 │ 6  192.168.55.80   (00:0e:c6:aa:bb:01)  arp-only  no ping reply, ARP REACHABLE │
 │ 7  192.168.55.101                       alive     0.4 ms                       │
 │ 8  192.168.55.150                       alive     0.4 ms                       │
 ╰────────────────────────────────────────────────────────────────────────────────╯
Port-scan a host (1-8, Enter back to the menu):
```

The ARP table only lists hosts the gateway has exchanged traffic with
recently; `[p]` fills it with every host that answers on the network.

### Display

On a terminal, scan data (addresses, MACs, states, times) is bold or coloured
and helper text (hints, `#` notes, legends, table headers) is grey. Colours
are off when the output is piped or `NO_COLOR` is set, so the one-shot output
stays script-friendly. Unicode box and block characters are used on UTF-8
terminals; `--ascii` (or `NSG_ASCII=1`) forces plain ASCII.

## Options

| Option | Description |
|---|---|
| `host` | Target IP or hostname |
| `ports` | Single port (`502`), list (`80,443`) or range (`1-1024`) |
| `-i`, `--interactive` | Interactive console: ARP hosts, ping sweep, TCP sweep, live map |
| `--ascii` | Plain ASCII drawing (no Unicode box/block characters) |
| `--proto {tcp,udp}` | Protocol (default: `tcp`) |
| `--timeout S` | Per-port timeout in seconds (default: `1.5`) |
| `--workers N` | Parallel scans (default: `100`) |
| `--banner` | TCP: attempt a banner grab on open ports |
| `--open-only` | Print open ports only |
| `--version` | Print version and exit |

## Port states

**TCP**

- `open` — connection accepted.
- `closed` — actively refused (RST).
- `filtered` — no reply within the timeout (likely dropped by a firewall).
- `error` — the connection failed for another reason; the errno is printed
  (e.g. `EHOSTUNREACH (No route to host)`, `ENETUNREACH (Network is unreachable)`).

**UDP** (connectionless, so inherently ambiguous)

- `open` — an application-layer reply was received.
- `closed` — an ICMP port-unreachable was received.
- `open|filtered` — no reply (cannot tell open from filtered).
- `error` — any other socket error, with its errno.

For reliable UDP results against a specific service, replace the probe
`payload=b"\x00"` in `scan_udp()` with a real service query (e.g. a DNS packet
for port 53).

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 BBerry2020.
