# netlink - TCP/IP Network Link Checker

A production-ready TCP/IP network diagnostics tool written in pure C. Zero external dependencies.

## Features

| Feature | Description |
|---------|-------------|
| **Ping** | ICMP echo with microsecond RTT precision |
| **TCP Port** | Non-blocking connect check |
| **DNS** | IPv4 + IPv6 resolution + reverse DNS |
| **Interfaces** | Local network card info (getifaddrs) |
| **Traceroute** | UDP/ICMP TTL-based routing trace |
| **Monitor** | Continuous polling mode |
| **Concurrent** | Multi-target parallel check (poll) |
| **Report** | CSV / JSONL export |
| **Alert** | Webhook notification (Feishu compatible) |

## Compile

```bash
gcc netlink.c -o netlink -Wall -O2 -lm
```

## Quick Start

```bash
# View interfaces
sudo ./netlink -i

# Ping check
./netlink -h 8.8.8.8 -c 4

# TCP port check
./netlink -t google.com -p 80,443,22

# DNS resolution
./netlink -d www.baidu.com

# Traceroute (requires root)
sudo ./netlink -T 8.8.8.8

# Comprehensive check
./netlink --all -h 8.8.8.8 -p 80,443

# Continuous monitor
./netlink -m 8.8.8.8 -p 80 --interval 5

# Export report
./netlink -t google.com -p 80,443 --report out.csv --format csv

# Alert webhook
./netlink -h 8.8.8.8 --alert-webhook https://... --alert-loss 20
```

## Full Options

```
netlink [options]

  -h <host>       Ping host (ICMP echo)
  -c <n>          Ping count (default: 4)
  -w <ms>         Timeout in ms (default: 3000)

  -T <host>       Trace route to host (UDP/ICMP)
  -t <host>       TCP port check
  -p <ports>      Comma-separated ports (e.g. 80,443,22)
  -6              Force IPv6 mode

  -d <domain>     Resolve domain (A + AAAA)
  -i              Show local network interfaces

  -m <host>       Continuous monitor mode
  --interval <s>  Monitor interval (default: 1)

  -f <file>       Load targets from file (one per line)
  --concurrency <n>  Concurrent checks (default: 10)

  --report <f>    Write results to file
  --format <fmt> Format: csv | jsonl (default: csv)

  --alert-webhook <url>  POST alert on failure
  --alert-loss <pct>     Alert if loss > N% (default: 20)
  --alert-rtt <ms>       Alert if avg RTT > N ms (default: 1000)

  --help          Show this help
  --version       Show version
```

## Architecture

- Pure POSIX C (Linux / macOS compatible)
- No external library dependencies
- Non-blocking I/O with `poll()`
- Microsecond-precision timing via `clock_gettime(CLOCK_MONOTONIC)`
- `getifaddrs()` for portable interface enumeration
- Raw socket for traceroute (requires root)

## License

MIT
