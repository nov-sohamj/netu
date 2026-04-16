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
netu scan localhost                         # Scans top 100 ports (smart default)
netu scan localhost 80                      # Single port
netu scan localhost 1-1024                  # Port range
netu scan localhost --top-ports 1000        # Top 1000 ports
netu scan localhost --fast                  # Fast mode: 500ms timeout, 500 workers
netu scan localhost --retries 2 --rate-limit 10ms
```

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | `2s` | Connection timeout per port |
| `--workers` | `100` | Concurrent goroutines |
| `--retries` | `0` | Retry closed ports n times |
| `--rate-limit` | `0` | Delay between connections |
| `--top-ports` | `100` | Scan top N ports: `100` or `1000` |
| `--fast` | | Fast mode: 500ms timeout, 500 workers |
| `--json` | | Output as JSON |
| `--output` | | Write JSON results to a file |

### `netu check` — Check specific ports

```bash
netu check localhost 22 80 443
netu check 192.168.1.1 3306 5432 --timeout 5s --retries 1
```

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | `2s` | Connection timeout per port |
| `--retries` | `0` | Retry closed ports n times |
| `--json` | | Output as JSON |
| `--output` | | Write JSON results to a file |

### `netu top` — Scan top common ports

```bash
netu top localhost
netu top localhost --ports 1000
netu top localhost --fast
```

| Option | Default | Description |
|--------|---------|-------------|
| `--ports` | `100` | Number of top ports: `100` or `1000` |
| `--timeout` | `2s` | Connection timeout per port |
| `--workers` | `100` | Concurrent goroutines |
| `--fast` | | Fast mode |
| `--json` | | Output as JSON |
| `--output` | | Write JSON results to a file |

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
```

DNS results are cached for 5 minutes to speed up repeated lookups (used internally by `inspect` and the API service).

| Option | Default | Description |
|--------|---------|-------------|
| `--type` | auto | Record type: `a`, `aaaa`, `mx`, `ns`, `txt`, `cname` |
| `--json` | | Output as JSON |
| `--output` | | Write JSON results to a file |

### `netu http` — HTTP probe with security checks

```bash
netu http google.com
netu http http://localhost:8080 --timeout 5s
netu http example.com --benchmark 20      # Run 20 requests, report latency percentiles
netu http example.com --json --output result.json
```

Auto-adds `https://` if no scheme is provided. Reports HTTP status, response time, content size, headers, TLS details, and security checks (HSTS, CSP, X-Frame-Options, TLS version, cert expiry).

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | `10s` | Request timeout |
| `--benchmark` | | Run N requests and report latency stats (min/avg/max/p50/p95/p99) |
| `--json` | | Output as JSON |
| `--output` | | Write JSON results to a file |

### `netu inspect` — Full host inspection

```bash
netu inspect google.com
netu inspect example.com --json
```

Runs a comprehensive inspection combining DNS lookup (A/AAAA, NS, MX), top 100 port scan with service detection, HTTP probe with security checks, and TLS certificate chain inspection. The fastest way to get a complete picture of a host.

| Option | Default | Description |
|--------|---------|-------------|
| `--json` | | Output as JSON |
| `--output` | | Write JSON results to a file |

### `netu cert` — TLS certificate inspector

```bash
netu cert google.com
netu cert localhost --port 8443
```

Shows the full TLS certificate chain: subject, issuer, SANs, validity, days until expiry, serial, signature algorithm, key usage, CA status.

| Option | Default | Description |
|--------|---------|-------------|
| `--port` | `443` | Port to connect to |
| `--timeout` | `5s` | Connection timeout |
| `--json` | | Output as JSON |
| `--output` | | Write JSON results to a file |

### `netu diff` — Compare JSON results

```bash
netu scan localhost --json --output before.json
# ... time passes ...
netu scan localhost --json --output after.json
netu diff before.json after.json
```

Compares two JSON result files and shows what was added, removed, or changed. Useful for tracking infrastructure changes over time.

| Option | Default | Description |
|--------|---------|-------------|
| `--json` | | Output diff as JSON |

### `netu monitor` — Continuous port monitor

```bash
netu monitor localhost 5432
netu monitor 192.168.1.1 80 --interval 10s
netu monitor localhost 8080 --verbose
```

Monitors a port and logs UP/DOWN transitions with colored output. Runs until Ctrl+C.

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
```

Connects to a port and reads the service banner. Auto-detects SSH, SMTP, FTP, HTTP, MySQL, Redis, MongoDB.

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | `5s` | Connection timeout |
| `--json` | | Output as JSON |
| `--output` | | Write JSON results to a file |

### `netu ping` — TCP ping

```bash
netu ping localhost 22
netu ping google.com 443 --count 10
```

TCP-based ping (no root required). Reports per-ping RTT and summary stats (min/avg/max, packet loss).

| Option | Default | Description |
|--------|---------|-------------|
| `--count` | `4` | Number of pings |
| `--timeout` | `2s` | Connection timeout per ping |
| `--json` | | Output as JSON |
| `--output` | | Write JSON results to a file |

### `netu trace` — Traceroute

```bash
sudo netu trace google.com
sudo netu trace 8.8.8.8 --hops 20
```

UDP traceroute with raw ICMP sockets. Shows per-hop address, reverse DNS, and latency. Requires root/sudo.

| Option | Default | Description |
|--------|---------|-------------|
| `--hops` | `30` | Maximum number of hops |
| `--timeout` | `2s` | Timeout per hop |
| `--json` | | Output as JSON |
| `--output` | | Write JSON results to a file |

### `netu whois` — WHOIS lookup

```bash
netu whois google.com
netu whois 8.8.8.8
```

Queries the appropriate WHOIS server based on TLD or IP range. Supports 15+ TLD servers.

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | `10s` | Query timeout |
| `--json` | | Output as JSON |
| `--output` | | Write JSON results to a file |

### `netu serve` — HTTP API service

```bash
netu serve
netu serve --addr 127.0.0.1:9090
NETU_API_KEY=secret netu serve    # Enable API key auth
```

Runs netu as an HTTP API with rate limiting (60 req/min per IP), request logging, and input validation.

| Endpoint | Description | Example |
|----------|-------------|---------|
| `GET /health` | Health check | `/health` |
| `GET /scan` | Scan port range | `/scan?host=localhost&ports=1-1024` |
| `GET /check` | Check specific ports | `/check?host=localhost&ports=22,80,443` |
| `GET /lookup` | DNS lookup (cached) | `/lookup?target=google.com&type=mx` |

**API security:**
- Rate limit: 60 requests/minute per IP (returns `429` when exceeded)
- API key auth: Set `NETU_API_KEY` env var to require `X-API-Key` header or `?key=` param
- Input validation: Host format, port ranges (1-65535), scan range cap (10000), timeout cap (30s)
- Request logging: All requests logged with IP, method, path, and duration

| Option | Default | Description |
|--------|---------|-------------|
| `--addr` | `0.0.0.0:8080` | Listen address |

## Global flags

| Flag | Description |
|------|-------------|
| `--help`, `-h` | Show help |
| `--json` | Output results as JSON (all commands) |
| `--output <file>` | Write JSON results to a file (all commands) |

## Color output

All commands use colored terminal output (green for open/pass, red for closed/fail, yellow for warnings). Color is automatically disabled when:
- `NO_COLOR` environment variable is set
- Output is piped (not a TTY)

## JSON output

```bash
# Pipe to jq
netu check localhost 22 80 --json | jq '.[] | select(.open)'

# Save results to file
netu inspect google.com --json --output google.json

# Compare results over time
netu diff before.json after.json

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
├── main.go              # CLI entry point (16 commands)
├── scanner/
│   ├── scanner.go       # Port scanning (scan, check, watch)
│   ├── top.go           # Top 100/1000 port lists
│   └── services.go      # Port-to-service name mapping
├── lookup/
│   ├── lookup.go        # DNS lookups (A/AAAA/MX/NS/TXT/CNAME/PTR)
│   └── cache.go         # In-memory DNS cache (5min TTL)
├── probe/
│   └── probe.go         # HTTP probing with security checks
├── cert/
│   └── cert.go          # TLS certificate chain inspection
├── inspect/
│   └── inspect.go       # Combined host inspection
├── diff/
│   └── diff.go          # JSON result comparison
├── output/
│   └── color.go         # Terminal color utilities
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
│   └── service.go       # HTTP API server (rate limit, auth, validation)
├── setup.sh             # Multi-OS installer
└── go.mod
```

## Requirements

- Go 1.21+
- No external dependencies
- `netu trace` requires root/sudo
