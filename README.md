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
```

### Examples

```sh
nsgscanner 192.168.55.56 502                        # single TCP port
nsgscanner 192.168.55.56 80,443,502 --banner        # list + banner grab
nsgscanner 192.168.55.56 1-1024 --workers 200 --open-only
nsgscanner 192.168.55.56 53 --proto udp             # UDP
```

## Options

| Option | Description |
|---|---|
| `host` | Target IP or hostname |
| `ports` | Single port (`502`), list (`80,443`) or range (`1-1024`) |
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
