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

`nsgscanner --interactive` (or `-i`) opens a menu of checks:

```text
  [Enter] hosts in the ARP table: pick one and scan its ports
  [p]     ping all hosts of a network
  [t]     TCP port(s) of your choice on all hosts of a network
  [m]     type a host and scan its ports
  Ctrl+C  exit
```

- **`[Enter]` ARP hosts** — lists the neighbours in the ARP table (`ip neigh`,
  or `/proc/net/arp` when the `ip` command is missing) as `IP (MAC)` pairs.
  Pick one, enter ports and protocol, and watch the results live.
- **`[p]` ping all** — choose a network directly connected to the gateway
  (read from its interfaces with `ip addr`, or `/proc/net/route`) or type any
  CIDR up to `/16`, then every address is pinged with the system `ping`
  command. Hosts that answer ARP but block ICMP are listed as `arp-only`.
- **`[t]` TCP port on all** — same network choice, then the port(s) you pick
  are checked on every address: `open` means the service is up, `closed` means
  the host is up but refuses the port; addresses with no answer are only
  counted.
- **`[m]`** — type a host and scan its ports.

After `[p]` and `[t]` the hosts found are listed and you can pick one to scan
its ports. Every run shows results live with a progress line and per-state
counters; runs above 1024 probes ask for confirmation first.

`Ctrl+C` during a scan or check stops it and returns to the menu; `Ctrl+C` at
the menu exits. `--timeout`, `--workers` and `--banner` apply to every run.

```text
> t
    #  IFACE         NETWORK             HOSTS
    1  VLAN1         192.168.55.0/24     254     this host: 192.168.55.254
Select network [1-1], c=custom CIDR, Enter=back: 1
Ports [22,80,443]: 502
# TCP 502 on 192.168.55.0/24 | 253 address(es), 253 probe(s) | timeout 1.5s | Ctrl+C stops
  192.168.55.56     502/tcp  open              1.2 ms  (c0:cd:d6:c3:56:dc)
  192.168.55.80     502/tcp  closed            0.9 ms  (00:0e:c6:aa:bb:01)
# 253/253 probes | open 1, closed 1, filtered 251 | 4.02s
# 1 host(s) with open port(s), 1 up with the port(s) closed
```

The ARP table only lists hosts the gateway has exchanged traffic with
recently; `[p]` fills it with every host that answers on the network.

## Options

| Option | Description |
|---|---|
| `host` | Target IP or hostname |
| `ports` | Single port (`502`), list (`80,443`) or range (`1-1024`) |
| `-i`, `--interactive` | Interactive menu: ARP hosts, ping all, TCP port on all, live results |
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
