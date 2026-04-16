package main

var helpTexts = map[string]string{
	"scan": `netu scan — scan a port or range of ports on a host

Usage:
  netu scan <host> [port|start-end] [options]

If no port is specified, scans the top 100 ports.

Options:
  --timeout duration    Connection timeout per port (default: 2s)
  --workers n           Number of concurrent goroutines (default: 100)
  --retries n           Retry closed ports n times (default: 0)
  --rate-limit duration Delay between connections (default: 0)
  --fast                Fast mode: 500ms timeout, 500 workers
  --top-ports n         Scan top N ports: 100 or 1000 (default: 100)
  --json                Output results as JSON

Examples:
  netu scan localhost
  netu scan localhost 1-1024
  netu scan 192.168.1.1 20-100 --timeout 5s --workers 200
  netu scan localhost --top-ports 1000
  netu scan localhost --fast
  netu scan localhost --retries 2 --rate-limit 10ms`,

	"check": `netu check — check specific ports on a host

Usage:
  netu check <host> <port> [port...] [options]

Options:
  --timeout duration    Connection timeout per port (default: 2s)
  --retries n           Retry closed ports n times (default: 0)
  --json                Output results as JSON

Examples:
  netu check localhost 22 80 443
  netu check 192.168.1.1 3306 5432 --timeout 5s --retries 1
  netu check localhost 22 80 --json`,

	"watch": `netu watch — wait for a port to come up

Usage:
  netu watch <host> <port> [options]

Options:
  --timeout duration    How long to wait overall (default: 30s)
  --interval duration   How often to retry (default: 1s)
  --json                Output result as JSON

Examples:
  netu watch localhost 5432 --timeout 60s
  netu watch localhost 8080 --interval 2s`,

	"lookup": `netu lookup — DNS lookup for a domain or IP

Usage:
  netu lookup <domain|ip> [options]

Options:
  --type type   Record type: a, aaaa, mx, ns, txt, cname (default: auto-detect)
  --json        Output results as JSON

If the target is an IP address, reverse lookup (PTR) is used automatically.

Record types:
  a       IPv4 addresses
  aaaa    IPv6 addresses
  mx      Mail exchange servers
  ns      Name servers
  txt     TXT records
  cname   Canonical name
  ptr     Reverse lookup (auto for IP input)

Examples:
  netu lookup google.com
  netu lookup google.com --type mx
  netu lookup 8.8.8.8
  netu lookup google.com --json`,

	"top": `netu top — scan the top common ports on a host

Usage:
  netu top <host> [options]

Options:
  --ports n            Number of top ports: 100 or 1000 (default: 100)
  --timeout duration   Connection timeout per port (default: 2s)
  --workers n          Number of concurrent goroutines (default: 100)
  --fast               Fast mode: 500ms timeout, 500 workers
  --json               Output results as JSON

Examples:
  netu top localhost
  netu top localhost --ports 1000
  netu top localhost --fast
  netu top 192.168.1.1 --timeout 5s`,

	"http": `netu http — probe a URL for status, timing, headers, TLS, and security

Usage:
  netu http <url> [options]

Auto-adds https:// if no scheme is provided.

Options:
  --timeout duration   Request timeout (default: 10s)
  --benchmark n        Run n requests and report latency percentiles
  --json               Output results as JSON
  --output file        Write JSON results to a file

Reports:
  - HTTP status code and response time
  - Content length and response headers
  - TLS certificate details, version, and days until expiry
  - Security checks: TLS version, cert expiry, HSTS, CSP, X-Frame-Options, etc.

Examples:
  netu http google.com
  netu http http://localhost:8080
  netu http example.com --timeout 5s
  netu http example.com --json
  netu http example.com --benchmark 20
  netu http example.com --json --output result.json`,

	"diff": `netu diff — compare two JSON result files

Usage:
  netu diff <file1.json> <file2.json> [options]

Options:
  --json   Output diff as JSON

Compares two JSON result files (from --output) and shows what changed.
Useful for tracking infrastructure changes over time.

Examples:
  netu scan localhost --json --output before.json
  # ... time passes ...
  netu scan localhost --json --output after.json
  netu diff before.json after.json`,

	"inspect": `netu inspect — full inspection of a host

Usage:
  netu inspect <host> [options]

Options:
  --json   Output results as JSON

Runs a comprehensive inspection combining:
  - DNS lookup (A/AAAA, NS, MX records)
  - Top 100 port scan with service detection
  - HTTP probe with security checks
  - TLS certificate chain inspection

This is the fastest way to get a complete picture of a host.

Examples:
  netu inspect google.com
  netu inspect example.com --json`,

	"cert": `netu cert — inspect TLS certificate on a host

Usage:
  netu cert <host> [options]

Options:
  --port n             Port to connect to (default: 443)
  --timeout duration   Connection timeout (default: 5s)
  --json               Output results as JSON

Shows the full TLS certificate chain with:
  - Subject and Issuer
  - Subject Alternative Names (SANs)
  - Validity dates and days until expiry
  - Serial number and signature algorithm
  - Key usage and whether the cert is a CA

Examples:
  netu cert google.com
  netu cert localhost --port 8443
  netu cert example.com --json`,

	"monitor": `netu monitor — continuously monitor a port

Usage:
  netu monitor <host> <port> [options]

Options:
  --interval duration   Check frequency (default: 5s)
  --timeout duration    Connection timeout per check (default: 2s)
  --verbose             Log every check, not just state changes
  --json                Output events as JSON lines

Monitors a port and logs UP/DOWN transitions. Runs until interrupted
with Ctrl+C. In default mode, only state changes are logged. Use
--verbose to see every check.

Examples:
  netu monitor localhost 5432
  netu monitor 192.168.1.1 80 --interval 10s
  netu monitor localhost 8080 --verbose
  netu monitor localhost 3306 --json`,

	"banner": `netu banner — grab service banner from a port

Usage:
  netu banner <host> <port> [options]

Options:
  --timeout duration   Connection timeout (default: 5s)
  --json               Output results as JSON

Connects to a port and reads the service banner. Auto-detects protocols
like SSH, SMTP, FTP, HTTP, MySQL, Redis, etc. For HTTP ports, sends a
HEAD request to get the server response.

Examples:
  netu banner localhost 22
  netu banner smtp.gmail.com 587
  netu banner localhost 3306 --json`,

	"whois": `netu whois — domain/IP WHOIS lookup

Usage:
  netu whois <domain|ip> [options]

Options:
  --timeout duration   Query timeout (default: 10s)
  --json               Output results as JSON

Queries the appropriate WHOIS server based on the TLD or IP range.
Returns registration info, expiry dates, registrar, name servers, etc.

Examples:
  netu whois google.com
  netu whois 8.8.8.8
  netu whois example.io --json`,

	"trace": `netu trace — traceroute to a host

Usage:
  netu trace <host> [options]

Options:
  --hops n             Maximum number of hops (default: 30)
  --timeout duration   Timeout per hop (default: 2s)
  --json               Output results as JSON

Sends UDP probes with increasing TTL to trace the network path.
Requires root/sudo for raw socket access.

Examples:
  sudo netu trace google.com
  sudo netu trace 8.8.8.8 --hops 20
  sudo netu trace google.com --json`,

	"ping": `netu ping — TCP ping a host with latency stats

Usage:
  netu ping <host> <port> [options]

Options:
  --count n            Number of pings to send (default: 4)
  --timeout duration   Connection timeout per ping (default: 2s)
  --json               Output results as JSON

Uses TCP connect (no root required). Reports per-ping RTT and
summary stats (min/avg/max latency, packet loss).

Examples:
  netu ping localhost 22
  netu ping google.com 443 --count 10
  netu ping localhost 8080 --json`,

	"serve": `netu serve — run netu as an HTTP API service

Usage:
  netu serve [options]

Options:
  --addr address   Address to listen on (default: 0.0.0.0:8080)

API Endpoints:
  GET /health                              Health check
  GET /scan?host=H&ports=1-1024            Scan port range
  GET /check?host=H&ports=22,80,443        Check specific ports
  GET /lookup?target=google.com&type=mx    DNS lookup

Query parameters for /scan:
  host       Target host (required)
  ports      Port or range, e.g. 80 or 1-1024 (required)
  timeout    Connection timeout (e.g. 2s)
  workers    Concurrent goroutines (e.g. 100)

Query parameters for /check:
  host       Target host (required)
  ports      Comma-separated ports (required)
  timeout    Connection timeout (e.g. 2s)

Query parameters for /lookup:
  target     Domain or IP (required)
  type       Record type: a, aaaa, mx, ns, txt, cname

Examples:
  netu serve
  netu serve --addr 127.0.0.1:9090`,
}
