# netu

Lightweight network toolkit built with Go. Port scanning, DNS lookup, HTTP probing, TLS inspection, service banner grabbing, WHOIS, traceroute, and more — zero external dependencies.

## Install

```bash
# Clone and build
git clone https://github.com/nov-sohamj/netu.git
cd netu
go build -o netu .

# Or install directly
go install github.com/nov-sohamj/netu@latest
```

### System service setup

```bash
# Install binary + register as a system service (Linux/macOS/Windows)
./setup.sh install

# Remove everything
./setup.sh uninstall
```

## Commands

### `netu scan` — Scan a port range

```bash
netu scan localhost 80
netu scan localhost 1-1024
netu scan 192.168.1.1 20-100 --timeout 5s --workers 200
```

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | `2s` | Connection timeout per port |
| `--workers` | `100` | Concurrent goroutines |
| `--json` | | Output as JSON |

### `netu check` — Check specific ports

```bash
netu check localhost 22 80 443
netu check 192.168.1.1 3306 5432 --timeout 5s
```

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | `2s` | Connection timeout per port |
| `--json` | | Output as JSON |

### `netu top` — Scan top 100 common ports

```bash
netu top localhost
netu top 192.168.1.1 --timeout 5s
```

Scans the top 100 most commonly used ports including SSH (22), HTTP (80), HTTPS (443), databases, and other well-known services.

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | `2s` | Connection timeout per port |
| `--workers` | `100` | Concurrent goroutines |
| `--json` | | Output as JSON |

### `netu watch` — Wait for a port to come up

```bash
netu watch localhost 5432 --timeout 60s
netu watch localhost 8080 --interval 2s
```

Polls a port until it opens or the timeout expires. Useful for waiting on containers or services to start.

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | `30s` | Overall wait time |
| `--interval` | `1s` | Poll frequency |
| `--json` | | Output as JSON |

### `netu lookup` — DNS lookup

```bash
netu lookup google.com                # Forward lookup (A/AAAA)
netu lookup 8.8.8.8                   # Reverse lookup (PTR)
netu lookup google.com --type mx      # Mail servers
netu lookup google.com --type ns      # Name servers
netu lookup google.com --type txt     # TXT records
netu lookup google.com --type cname   # Canonical name
netu lookup google.com --type a       # IPv4 only
netu lookup google.com --type aaaa    # IPv6 only
```

| Option | Default | Description |
|--------|---------|-------------|
| `--type` | auto | Record type: `a`, `aaaa`, `mx`, `ns`, `txt`, `cname` |
| `--json` | | Output as JSON |

### `netu http` — HTTP probe

```bash
netu http https://google.com
netu http http://localhost:8080 --timeout 5s
```

Reports HTTP status, response time, content size, response headers, and TLS certificate details (expiry, issuer, subject).

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | `10s` | Request timeout |
| `--json` | | Output as JSON |

### `netu cert` — TLS certificate inspector

```bash
netu cert google.com
netu cert localhost --port 8443
netu cert example.com --json
```

Inspects the full TLS certificate chain with subject, issuer, SANs, validity dates, days until expiry, serial number, signature algorithm, key usage, and CA status. Works with self-signed certs.

| Option | Default | Description |
|--------|---------|-------------|
| `--port` | `443` | Port to connect to |
| `--timeout` | `5s` | Connection timeout |
| `--json` | | Output as JSON |

### `netu monitor` — Continuous port monitor

```bash
netu monitor localhost 5432
netu monitor 192.168.1.1 80 --interval 10s
netu monitor localhost 8080 --verbose
```

Monitors a port and logs UP/DOWN transitions. Runs until interrupted with Ctrl+C. In default mode, only state changes are logged. Use `--verbose` to see every check.

| Option | Default | Description |
|--------|---------|-------------|
| `--interval` | `5s` | Check frequency |
| `--timeout` | `2s` | Connection timeout per check |
| `--verbose` | | Log every check, not just state changes |
| `--json` | | Output events as JSON lines |

### `netu banner` — Service banner grab

```bash
netu banner localhost 22
netu banner smtp.gmail.com 587
netu banner localhost 3306 --json
```

Connects to a port and reads the service banner. Auto-detects protocols like SSH, SMTP, FTP, HTTP, MySQL, Redis, and MongoDB. For HTTP ports, sends a HEAD request to get the server response.

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | `5s` | Connection timeout |
| `--json` | | Output as JSON |

### `netu ping` — TCP ping

```bash
netu ping localhost 22
netu ping google.com 443 --count 10
netu ping localhost 8080 --json
```

TCP-based ping (no root required). Reports per-ping RTT and summary stats (min/avg/max latency, packet loss).

| Option | Default | Description |
|--------|---------|-------------|
| `--count` | `4` | Number of pings to send |
| `--timeout` | `2s` | Connection timeout per ping |
| `--json` | | Output as JSON |

### `netu trace` — Traceroute

```bash
sudo netu trace google.com
sudo netu trace 8.8.8.8 --hops 20
sudo netu trace google.com --json
```

Sends UDP probes with increasing TTL to trace the network path. Shows per-hop address, reverse DNS, and latency. Requires root/sudo for raw socket access.

| Option | Default | Description |
|--------|---------|-------------|
| `--hops` | `30` | Maximum number of hops |
| `--timeout` | `2s` | Timeout per hop |
| `--json` | | Output as JSON |

### `netu whois` — WHOIS lookup

```bash
netu whois google.com
netu whois 8.8.8.8
netu whois example.io --json
```

Queries the appropriate WHOIS server based on the TLD or IP range. Returns registration info, expiry dates, registrar, name servers, etc. Supports 15+ TLD servers out of the box.

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | `10s` | Query timeout |
| `--json` | | Output as JSON |

### `netu serve` — HTTP API service

```bash
netu serve
netu serve --addr 127.0.0.1:9090
```

Runs netu as an HTTP API. Endpoints:

| Endpoint | Description | Example |
|----------|-------------|---------|
| `GET /health` | Health check | `/health` |
| `GET /scan` | Scan port range | `/scan?host=localhost&ports=1-1024` |
| `GET /check` | Check specific ports | `/check?host=localhost&ports=22,80,443` |
| `GET /lookup` | DNS lookup | `/lookup?target=google.com&type=mx` |

| Option | Default | Description |
|--------|---------|-------------|
| `--addr` | `0.0.0.0:8080` | Listen address |

## JSON output

All commands support `--json` for scriptable output:

```bash
# Pipe to jq
netu check localhost 22 80 --json | jq '.[] | select(.Open)'

# Use in scripts
if netu watch localhost 5432 --timeout 10s --json | jq -e '.up' > /dev/null; then
  echo "Database is ready"
fi
```

## Help

```bash
netu --help              # Global help
netu help <command>      # Command-specific help
netu <command> --help    # Same thing
```

## Project structure

```
netu/
├── main.go              # CLI entry point
├── scanner/
│   ├── scanner.go       # Port scanning (scan, check, watch)
│   └── top.go           # Top 100 common ports list
├── lookup/
│   └── lookup.go        # DNS lookups
├── probe/
│   └── probe.go         # HTTP probing
├── cert/
│   └── cert.go          # TLS certificate inspection
├── monitor/
│   └── monitor.go       # Continuous port monitoring
├── banner/
│   └── banner.go        # Service banner grabbing
├── ping/
│   └── ping.go          # TCP ping
├── trace/
│   └── trace.go         # Traceroute
├── whois/
│   └── whois.go         # WHOIS lookups
├── service/
│   └── service.go       # HTTP API server
├── setup.sh             # Multi-OS installer
└── go.mod
```

## Requirements

- Go 1.21+
- No external dependencies
- `netu trace` requires root/sudo
