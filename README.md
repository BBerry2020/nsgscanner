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

`nsgscanner --interactive` (or `-i`) opens a menu for scanning hosts directly
connected to the gateway:

1. Press any key to list the neighbours in the ARP table (`ip neigh`, or
   `/proc/net/arp` when the `ip` command is missing) as `IP (MAC address)`
   pairs, or press `m` to type a host.
2. Pick a host by number, then enter the ports and the protocol.
3. Results appear live as each port is probed, with a progress line and
   per-state counters. Up to 64 ports every result is listed; above that only
   open ports are listed and the other states are counted.

`Ctrl+C` during a scan stops it and returns to the menu; `Ctrl+C` at the menu
exits. `--timeout`, `--workers` and `--banner` apply to every interactive scan.

```text
    #  IP               (MAC)                IFACE       STATE
    1  192.168.55.1     (3c:22:fb:11:22:33)  eth1        STALE
    2  192.168.55.56    (00:1d:9c:aa:bb:cc)  eth1        REACHABLE
Select host [1-2], r=refresh, m=manual, Enter=back: 2

Target: 192.168.55.56 (00:1d:9c:aa:bb:cc)
Ports [1-1024]: 502
Protocol [t]cp / [u]dp (Enter = tcp):
# target 192.168.55.56 (00:1d:9c:aa:bb:cc) | TCP | 1 port(s) | timeout 1.5s | Ctrl+C stops the scan
  502/tcp  open              1.2 ms
# 1/1 scanned | open 1 | 0.00s
```

The ARP table only lists hosts the gateway has exchanged traffic with
recently; use `m` to scan any other host.

## Options

| Option | Description |
|---|---|
| `host` | Target IP or hostname |
| `ports` | Single port (`502`), list (`80,443`) or range (`1-1024`) |
| `-i`, `--interactive` | Interactive menu: pick a host from the ARP table, live scan |
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
