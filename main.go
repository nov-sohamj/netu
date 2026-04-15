package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"time"

	"netu/banner"
	"netu/cert"
	"netu/diff"
	"netu/inspect"
	"netu/lookup"
	"netu/monitor"
	"netu/output"
	"netu/ping"
	"netu/probe"
	"netu/scanner"
	"netu/service"
	"netu/trace"
	"netu/whois"
)

const defaultTimeout = 2 * time.Second
const defaultWorkers = 100

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

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	if cmd == "--help" || cmd == "-h" {
		printUsage()
		return
	}

	if cmd == "help" {
		if len(os.Args) < 3 {
			printUsage()
			return
		}
		printCommandHelp(os.Args[2])
		return
	}

	for _, arg := range os.Args[2:] {
		if arg == "--help" || arg == "-h" {
			printCommandHelp(cmd)
			return
		}
	}

	switch cmd {
	case "scan":
		cmdScan(os.Args[2:])
	case "check":
		cmdCheck(os.Args[2:])
	case "watch":
		cmdWatch(os.Args[2:])
	case "lookup":
		cmdLookup(os.Args[2:])
	case "top":
		cmdTop(os.Args[2:])
	case "http":
		cmdHTTP(os.Args[2:])
	case "ping":
		cmdPing(os.Args[2:])
	case "inspect":
		cmdInspect(os.Args[2:])
	case "cert":
		cmdCert(os.Args[2:])
	case "monitor":
		cmdMonitor(os.Args[2:])
	case "banner":
		cmdBanner(os.Args[2:])
	case "trace":
		cmdTrace(os.Args[2:])
	case "whois":
		cmdWhois(os.Args[2:])
	case "diff":
		cmdDiff(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printCommandHelp(cmd string) {
	text, ok := helpTexts[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
	fmt.Println(text)
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func getFlagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// writeOutput writes JSON data to a file if --output is specified.
func writeOutput(args []string, v interface{}) {
	outFile := getFlagValue(args, "--output")
	if outFile == "" {
		return
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %s\n", err)
		return
	}
	if err := os.WriteFile(outFile, append(data, '\n'), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %s\n", outFile, err)
	} else {
		fmt.Fprintf(os.Stderr, "Results written to %s\n", outFile)
	}
}

// netu scan <host> [port|start-end] [flags]
func cmdScan(args []string) {
	if len(args) < 1 {
		printCommandHelp("scan")
		os.Exit(1)
	}

	host := args[0]
	opts := scanner.DefaultOptions()
	jsonOut := hasFlag(args, "--json")
	fast := hasFlag(args, "--fast")
	topPorts := 0
	useTopPorts := false

	if fast {
		opts = scanner.FastOptions()
	}

	// Check if second arg is a port/range or a flag
	var startPort, endPort int
	rangeSpecified := false
	argStart := 1
	if len(args) > 1 && !strings.HasPrefix(args[1], "--") {
		var err error
		parts := strings.SplitN(args[1], "-", 2)
		if len(parts) == 1 {
			startPort, err = strconv.Atoi(parts[0])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid port: %s\n", parts[0])
				os.Exit(1)
			}
			endPort = startPort
		} else {
			startPort, err = strconv.Atoi(parts[0])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid start port: %s\n", parts[0])
				os.Exit(1)
			}
			endPort, err = strconv.Atoi(parts[1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid end port: %s\n", parts[1])
				os.Exit(1)
			}
		}
		rangeSpecified = true
		argStart = 2
	}

	for i := argStart; i < len(args); i++ {
		var err error
		switch args[i] {
		case "--timeout":
			i++
			opts.Timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
		case "--workers":
			i++
			opts.Workers, err = strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid workers: %s\n", args[i])
				os.Exit(1)
			}
		case "--retries":
			i++
			opts.Retries, err = strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid retries: %s\n", args[i])
				os.Exit(1)
			}
		case "--rate-limit":
			i++
			opts.RateLimit, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid rate-limit: %s\n", args[i])
				os.Exit(1)
			}
		case "--top-ports":
			i++
			topPorts, err = strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid top-ports: %s\n", args[i])
				os.Exit(1)
			}
			useTopPorts = true
		case "--output":
			i++ // skip filename
		}
	}

	// Smart default: if no range and no --top-ports, use top 100
	if !rangeSpecified && !useTopPorts {
		useTopPorts = true
		topPorts = 100
	}

	var results []scanner.Result
	if useTopPorts {
		portList := scanner.Top100
		if topPorts >= 1000 {
			portList = scanner.Top1000
		}
		results = scanner.CheckPorts(host, portList, opts)
		if !jsonOut {
			fmt.Printf("Scanning top %d ports on %s ...\n\n", len(portList), host)
		}
	} else {
		results = scanner.ScanPorts(host, startPort, endPort, opts)
		if !jsonOut {
			fmt.Printf("Scanning %s ports %d-%d ...\n\n", host, startPort, endPort)
		}
	}

	if jsonOut {
		printJSON(results)
		writeOutput(args, results)
		return
	}

	open := 0
	for _, r := range results {
		if r.Open {
			svc := ""
			if r.Service != "" {
				svc = " (" + output.Cyan(r.Service) + ")"
			}
			fmt.Printf("  %-6d %s %s\n", r.Port, output.PortState(true), svc)
			open++
		}
	}
	total := len(results)
	if open == 0 {
		fmt.Println("  No open ports found.")
	}
	fmt.Printf("\n%s/%d ports open\n", output.Bold(fmt.Sprintf("%d", open)), total)
}

// netu check <host> <port> [port...] [flags]
func cmdCheck(args []string) {
	if len(args) < 2 {
		printCommandHelp("check")
		os.Exit(1)
	}

	host := args[0]
	opts := scanner.DefaultOptions()
	jsonOut := hasFlag(args, "--json")
	var ports []int

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--timeout":
			i++
			var err error
			opts.Timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
		case "--retries":
			i++
			var err error
			opts.Retries, err = strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid retries: %s\n", args[i])
				os.Exit(1)
			}
		case "--json":
			continue
		case "--output":
			i++ // skip the filename
		default:
			p, err := strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid port: %s\n", args[i])
				os.Exit(1)
			}
			ports = append(ports, p)
		}
	}

	results := scanner.CheckPorts(host, ports, opts)

	if jsonOut {
		printJSON(results)
		writeOutput(args, results)
		return
	}

	fmt.Printf("Checking %d port(s) on %s ...\n\n", len(ports), host)
	for _, r := range results {
		svc := ""
		if r.Service != "" {
			svc = " (" + output.Cyan(r.Service) + ")"
		}
		fmt.Printf("  %-6d %s %s\n", r.Port, output.PortState(r.Open), svc)
	}
}

// netu watch <host> <port> [--timeout duration] [--interval duration] [--json]
func cmdWatch(args []string) {
	if len(args) < 2 {
		printCommandHelp("watch")
		os.Exit(1)
	}

	host := args[0]
	port, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid port: %s\n", args[1])
		os.Exit(1)
	}

	timeout := 30 * time.Second
	interval := 1 * time.Second
	jsonOut := hasFlag(args, "--json")

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--timeout":
			i++
			timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
		case "--interval":
			i++
			interval, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid interval: %s\n", args[i])
				os.Exit(1)
			}
		case "--output":
			i++
		}
	}

	if !jsonOut {
		fmt.Printf("Watching %s:%d (timeout %s, poll every %s) ...\n", host, port, timeout, interval)
	}

	result := scanner.WatchPort(host, port, timeout, interval)

	if jsonOut {
		printJSON(map[string]interface{}{
			"host":    host,
			"port":    port,
			"up":      result.Up,
			"elapsed": result.Elapsed.Round(time.Millisecond).String(),
		})
		if !result.Up {
			os.Exit(1)
		}
		return
	}

	if result.Up {
		fmt.Printf("Port %d is %s (took %s)\n", port, output.Green("UP"), result.Elapsed.Round(time.Millisecond))
	} else {
		fmt.Printf("Timed out after %s — port %d did not open.\n", result.Elapsed.Round(time.Millisecond), port)
		os.Exit(1)
	}
}

// netu lookup <domain|ip> [--type a|aaaa|mx|ns|txt|cname] [--json]
func cmdLookup(args []string) {
	if len(args) < 1 {
		printCommandHelp("lookup")
		os.Exit(1)
	}

	target := args[0]
	recordType := ""
	jsonOut := hasFlag(args, "--json")

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--type":
			i++
			recordType = strings.ToLower(args[i])
		case "--output":
			i++
		}
	}

	if lookup.IsIP(target) && recordType == "" {
		recordType = "ptr"
	}

	var result lookup.Result
	var err error

	switch recordType {
	case "ptr":
		result, err = lookup.Reverse(target)
	case "a":
		result, err = lookup.QueryA(target)
	case "aaaa":
		result, err = lookup.QueryAAAA(target)
	case "mx":
		result, err = lookup.QueryMX(target)
	case "ns":
		result, err = lookup.QueryNS(target)
	case "txt":
		result, err = lookup.QueryTXT(target)
	case "cname":
		result, err = lookup.QueryCNAME(target)
	default:
		result, err = lookup.Forward(target)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	if jsonOut {
		printJSON(result)
		writeOutput(args, result)
		return
	}

	fmt.Printf("Lookup: %s [%s]\n\n", output.Bold(target), output.Cyan(result.Type))
	for _, r := range result.Records {
		fmt.Printf("  %s\n", r)
	}
}

// netu top <host> [flags]
func cmdTop(args []string) {
	if len(args) < 1 {
		printCommandHelp("top")
		os.Exit(1)
	}

	host := args[0]
	opts := scanner.DefaultOptions()
	jsonOut := hasFlag(args, "--json")
	fast := hasFlag(args, "--fast")
	topN := 100

	if fast {
		opts = scanner.FastOptions()
	}

	for i := 1; i < len(args); i++ {
		var err error
		switch args[i] {
		case "--timeout":
			i++
			opts.Timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
		case "--workers":
			i++
			opts.Workers, err = strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid workers: %s\n", args[i])
				os.Exit(1)
			}
		case "--ports":
			i++
			topN, err = strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid ports: %s\n", args[i])
				os.Exit(1)
			}
		case "--output":
			i++
		}
	}

	portList := scanner.Top100
	if topN >= 1000 {
		portList = scanner.Top1000
	}

	results := scanner.CheckPorts(host, portList, opts)

	if jsonOut {
		printJSON(results)
		writeOutput(args, results)
		return
	}

	fmt.Printf("Scanning top %d ports on %s ...\n\n", len(portList), host)
	open := 0
	for _, r := range results {
		if r.Open {
			svc := ""
			if r.Service != "" {
				svc = " (" + output.Cyan(r.Service) + ")"
			}
			fmt.Printf("  %-6d %s %s\n", r.Port, output.PortState(true), svc)
			open++
		}
	}
	if open == 0 {
		fmt.Println("  No open ports found.")
	}
	fmt.Printf("\n%s/%d ports open\n", output.Bold(fmt.Sprintf("%d", open)), len(portList))
}

// netu http <url> [--timeout duration] [--benchmark n] [--json]
func cmdHTTP(args []string) {
	if len(args) < 1 {
		printCommandHelp("http")
		os.Exit(1)
	}

	url := args[0]
	timeout := 10 * time.Second
	jsonOut := hasFlag(args, "--json")
	benchN := 0

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--timeout":
			i++
			var err error
			timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
		case "--benchmark":
			i++
			var err error
			benchN, err = strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid benchmark count: %s\n", args[i])
				os.Exit(1)
			}
		case "--output":
			i++
		}
	}

	if benchN > 0 {
		cmdHTTPBenchmark(url, timeout, benchN, jsonOut, args)
		return
	}

	result, err := probe.HTTP(url, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	if jsonOut {
		printJSON(result)
		writeOutput(args, result)
		return
	}

	fmt.Printf("HTTP Probe: %s\n\n", output.Bold(result.URL))
	fmt.Printf("  Status:        %s\n", result.StatusText)
	fmt.Printf("  Response Time: %s\n", result.ResponseTime)
	fmt.Printf("  Content Size:  %d bytes\n", result.ContentLen)

	if result.TLS != nil {
		fmt.Printf("\n  TLS:\n")
		fmt.Printf("    Version:  %s\n", result.TLS.Version)
		fmt.Printf("    Subject:  %s\n", result.TLS.Subject)
		fmt.Printf("    Issuer:   %s\n", result.TLS.Issuer)
		fmt.Printf("    Expires:  %s (%d days left)\n", result.TLS.NotAfter, result.TLS.DaysLeft)
	}

	if len(result.SecurityChecks) > 0 {
		fmt.Printf("\n  Security Checks:\n")
		for _, sc := range result.SecurityChecks {
			fmt.Printf("    [%s] %-26s %s\n", output.Icon(sc.Status), sc.Name, sc.Detail)
		}
	}

	fmt.Printf("\n  Headers:\n")
	for _, h := range result.Headers {
		fmt.Printf("    %s: %s\n", output.Gray(h.Key+":"), h.Value)
	}
}

func cmdHTTPBenchmark(url string, timeout time.Duration, n int, jsonOut bool, args []string) {
	if !jsonOut {
		fmt.Printf("Benchmarking %s (%d requests) ...\n\n", output.Bold(url), n)
	}

	var durations []time.Duration
	var errors int

	for i := 0; i < n; i++ {
		output.Progress(i+1, n, "Requests")
		start := time.Now()
		_, err := probe.HTTP(url, timeout)
		elapsed := time.Since(start)
		if err != nil {
			errors++
			continue
		}
		durations = append(durations, elapsed)
	}

	if len(durations) == 0 {
		fmt.Fprintf(os.Stderr, "all %d requests failed\n", n)
		os.Exit(1)
	}

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })

	min := durations[0]
	max := durations[len(durations)-1]
	p50 := durations[len(durations)*50/100]
	p95 := durations[len(durations)*95/100]
	p99 := durations[len(durations)*99/100]

	var total time.Duration
	for _, d := range durations {
		total += d
	}
	avg := total / time.Duration(len(durations))

	benchResult := map[string]interface{}{
		"url":      url,
		"requests": n,
		"success":  len(durations),
		"errors":   errors,
		"min":      min.String(),
		"max":      max.String(),
		"avg":      avg.String(),
		"p50":      p50.String(),
		"p95":      p95.String(),
		"p99":      p99.String(),
	}

	if jsonOut {
		printJSON(benchResult)
		writeOutput(args, benchResult)
		return
	}

	fmt.Printf("  Requests:  %d total, %s success, %s errors\n",
		n, output.Green(fmt.Sprintf("%d", len(durations))), output.Red(fmt.Sprintf("%d", errors)))
	fmt.Printf("  Latency:\n")
	fmt.Printf("    Min:  %s\n", min)
	fmt.Printf("    Avg:  %s\n", avg)
	fmt.Printf("    Max:  %s\n", max)
	fmt.Printf("    P50:  %s\n", p50)
	fmt.Printf("    P95:  %s\n", p95)
	fmt.Printf("    P99:  %s\n", p99)
}

// netu ping <host> <port> [--count n] [--timeout duration] [--json]
func cmdPing(args []string) {
	if len(args) < 2 {
		printCommandHelp("ping")
		os.Exit(1)
	}

	host := args[0]
	port, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid port: %s\n", args[1])
		os.Exit(1)
	}

	count := 4
	timeout := defaultTimeout
	jsonOut := hasFlag(args, "--json")

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--count":
			i++
			count, err = strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid count: %s\n", args[i])
				os.Exit(1)
			}
		case "--timeout":
			i++
			timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
		case "--output":
			i++
		}
	}

	if !jsonOut {
		fmt.Printf("TCP PING %s:%d (%d pings) ...\n\n", host, port, count)
	}

	stats := ping.TCPPing(host, port, count, timeout)

	if jsonOut {
		printJSON(stats)
		writeOutput(args, stats)
		return
	}

	for _, p := range stats.Pings {
		if p.OK {
			fmt.Printf("  seq=%d rtt=%s\n", p.Seq, output.Green(p.RTT))
		} else {
			fmt.Printf("  seq=%d %s\n", p.Seq, output.Red("timeout"))
		}
	}

	fmt.Printf("\n--- %s ping stats ---\n", stats.Host)
	lossColor := output.Green
	if stats.LossPercent > 50 {
		lossColor = output.Red
	} else if stats.LossPercent > 0 {
		lossColor = output.Yellow
	}
	fmt.Printf("%d sent, %d received, %s loss\n", stats.Sent, stats.Received, lossColor(fmt.Sprintf("%.1f%%", stats.LossPercent)))
	if stats.Received > 0 {
		fmt.Printf("rtt min/avg/max = %s/%s/%s\n", stats.MinRTT, stats.AvgRTT, stats.MaxRTT)
	}
}

// netu inspect <host> [--json]
func cmdInspect(args []string) {
	if len(args) < 1 {
		printCommandHelp("inspect")
		os.Exit(1)
	}

	host := args[0]
	jsonOut := hasFlag(args, "--json")

	if !jsonOut {
		fmt.Printf("Inspecting %s ...\n", output.Bold(host))
	}

	result := inspect.Run(host)

	if jsonOut {
		printJSON(result)
		writeOutput(args, result)
		return
	}

	// DNS
	if result.DNS != nil {
		fmt.Printf("\n  %s\n", output.Bold("DNS:"))
		if len(result.DNS.IPs) > 0 {
			fmt.Printf("    IPs:  %s\n", strings.Join(result.DNS.IPs, ", "))
		}
		if len(result.DNS.NS) > 0 {
			fmt.Printf("    NS:   %s\n", strings.Join(result.DNS.NS, ", "))
		}
		if len(result.DNS.MX) > 0 {
			fmt.Printf("    MX:   %s\n", strings.Join(result.DNS.MX, ", "))
		}
	}

	// Ports
	if result.Ports != nil {
		fmt.Printf("\n  %s (%d/%d):\n", output.Bold("Open Ports"), len(result.Ports.Open), result.Ports.Total)
		if len(result.Ports.Open) == 0 {
			fmt.Printf("    none\n")
		}
		for _, p := range result.Ports.Open {
			svc := ""
			if p.Service != "" {
				svc = " (" + output.Cyan(p.Service) + ")"
			}
			fmt.Printf("    %-6d %s %s\n", p.Port, output.PortState(true), svc)
		}
	}

	// HTTP
	if result.HTTP != nil {
		fmt.Printf("\n  %s\n", output.Bold("HTTP:"))
		fmt.Printf("    URL:           %s\n", result.HTTP.URL)
		fmt.Printf("    Status:        %s\n", result.HTTP.StatusText)
		fmt.Printf("    Response Time: %s\n", result.HTTP.ResponseTime)
		if result.HTTP.TLS != nil {
			fmt.Printf("    TLS Version:   %s\n", result.HTTP.TLS.Version)
		}
		if len(result.HTTP.SecurityChecks) > 0 {
			fmt.Printf("\n  %s\n", output.Bold("Security:"))
			for _, sc := range result.HTTP.SecurityChecks {
				fmt.Printf("    [%s] %-26s %s\n", output.Icon(sc.Status), sc.Name, sc.Detail)
			}
		}
	}

	// TLS
	if result.TLS != nil && len(result.TLS.Chain) > 0 {
		leaf := result.TLS.Chain[0]
		fmt.Printf("\n  %s\n", output.Bold("TLS Certificate:"))
		fmt.Printf("    Subject:  %s\n", leaf.Subject)
		fmt.Printf("    Issuer:   %s\n", leaf.Issuer)
		fmt.Printf("    Expires:  %s (%d days left)\n", leaf.NotAfter, leaf.DaysLeft)
		fmt.Printf("    Version:  %s\n", result.TLS.TLSVersion)
	}

	// Errors
	if len(result.Errors) > 0 {
		fmt.Printf("\n  %s\n", output.Bold("Errors:"))
		for _, e := range result.Errors {
			fmt.Printf("    %s %s\n", output.Red("-"), e)
		}
	}

	fmt.Println()
}

// netu cert <host> [--port n] [--timeout duration] [--json]
func cmdCert(args []string) {
	if len(args) < 1 {
		printCommandHelp("cert")
		os.Exit(1)
	}

	host := args[0]
	port := 443
	timeout := 5 * time.Second
	jsonOut := hasFlag(args, "--json")

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--port":
			i++
			var err error
			port, err = strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid port: %s\n", args[i])
				os.Exit(1)
			}
		case "--timeout":
			i++
			var err error
			timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
		case "--output":
			i++
		}
	}

	result, err := cert.Inspect(host, port, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	if jsonOut {
		printJSON(result)
		writeOutput(args, result)
		return
	}

	fmt.Printf("TLS Certificate: %s:%d (%s)\n", output.Bold(result.Host), result.Port, output.Cyan(result.TLSVersion))
	for i, c := range result.Chain {
		if i == 0 {
			fmt.Printf("\n  Leaf Certificate:\n")
		} else {
			fmt.Printf("\n  Chain Certificate #%d:\n", i)
		}
		fmt.Printf("    Subject:    %s\n", c.Subject)
		fmt.Printf("    Issuer:     %s\n", c.Issuer)
		if len(c.SANs) > 0 {
			fmt.Printf("    SANs:       %s\n", strings.Join(c.SANs, ", "))
		}
		fmt.Printf("    Valid:      %s to %s (%d days left)\n", c.NotBefore, c.NotAfter, c.DaysLeft)
		fmt.Printf("    Serial:     %s\n", c.Serial)
		fmt.Printf("    Algorithm:  %s\n", c.SigAlgo)
		if len(c.KeyUsage) > 0 {
			fmt.Printf("    Key Usage:  %s\n", strings.Join(c.KeyUsage, ", "))
		}
		if c.IsCA {
			fmt.Printf("    CA:         yes\n")
		}
	}
}

// netu monitor <host> <port> [--interval duration] [--timeout duration] [--verbose] [--json]
func cmdMonitor(args []string) {
	if len(args) < 2 {
		printCommandHelp("monitor")
		os.Exit(1)
	}

	host := args[0]
	port, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid port: %s\n", args[1])
		os.Exit(1)
	}

	interval := 5 * time.Second
	timeout := defaultTimeout
	verbose := hasFlag(args, "--verbose")
	jsonOut := hasFlag(args, "--json")

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--interval":
			i++
			interval, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid interval: %s\n", args[i])
				os.Exit(1)
			}
		case "--timeout":
			i++
			timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
		case "--output":
			i++
		}
	}

	if !jsonOut {
		fmt.Printf("Monitoring %s:%d (every %s, Ctrl+C to stop) ...\n\n", host, port, interval)
	}

	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		close(stop)
	}()

	onEvent := func(e monitor.Event) {
		if jsonOut {
			printJSON(e)
		} else {
			status := output.Status(e.Status)
			if e.RTT != "" {
				fmt.Printf("  [%s] %s (rtt %s)\n", output.Gray(e.Time), status, e.RTT)
			} else {
				fmt.Printf("  [%s] %s\n", output.Gray(e.Time), status)
			}
		}
	}

	monitor.Run(host, port, interval, timeout, verbose, onEvent, stop)

	if !jsonOut {
		fmt.Println("\nMonitoring stopped.")
	}
}

// netu banner <host> <port> [--timeout duration] [--json]
func cmdBanner(args []string) {
	if len(args) < 2 {
		printCommandHelp("banner")
		os.Exit(1)
	}

	host := args[0]
	port, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid port: %s\n", args[1])
		os.Exit(1)
	}

	timeout := 5 * time.Second
	jsonOut := hasFlag(args, "--json")

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--timeout":
			i++
			timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
		case "--output":
			i++
		}
	}

	result, err := banner.Grab(host, port, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	if jsonOut {
		printJSON(result)
		writeOutput(args, result)
		return
	}

	fmt.Printf("Banner: %s:%d [%s]\n\n", output.Bold(result.Host), result.Port, output.Cyan(result.Proto))
	fmt.Println(result.Banner)
}

// netu whois <domain|ip> [--timeout duration] [--json]
func cmdWhois(args []string) {
	if len(args) < 1 {
		printCommandHelp("whois")
		os.Exit(1)
	}

	target := args[0]
	timeout := 10 * time.Second
	jsonOut := hasFlag(args, "--json")

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--timeout":
			i++
			var err error
			timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
		case "--output":
			i++
		}
	}

	result, err := whois.Lookup(target, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	if jsonOut {
		printJSON(result)
		writeOutput(args, result)
		return
	}

	fmt.Printf("WHOIS: %s (server: %s)\n\n", output.Bold(result.Target), output.Gray(result.Server))
	fmt.Println(result.Raw)
}

// netu trace <host> [--hops n] [--timeout duration] [--json]
func cmdTrace(args []string) {
	if len(args) < 1 {
		printCommandHelp("trace")
		os.Exit(1)
	}

	host := args[0]
	maxHops := 30
	timeout := defaultTimeout
	jsonOut := hasFlag(args, "--json")

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--hops":
			i++
			var err error
			maxHops, err = strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid hops: %s\n", args[i])
				os.Exit(1)
			}
		case "--timeout":
			i++
			var err error
			timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
		case "--output":
			i++
		}
	}

	result, err := trace.Trace(host, maxHops, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	if jsonOut {
		printJSON(result)
		writeOutput(args, result)
		return
	}

	fmt.Printf("Traceroute to %s (max %d hops)\n\n", output.Bold(result.Target), result.MaxHops)
	for _, h := range result.Hops {
		if h.OK {
			if h.Addr == h.Host {
				fmt.Printf("  %2d  %-40s  %s\n", h.TTL, h.Addr, output.Green(h.RTT))
			} else {
				fmt.Printf("  %2d  %s (%s)  %s\n", h.TTL, h.Host, output.Gray(h.Addr), output.Green(h.RTT))
			}
		} else {
			fmt.Printf("  %2d  %s\n", h.TTL, output.Red("*"))
		}
	}
}

// netu serve [--addr address]
func cmdServe(args []string) {
	addr := "0.0.0.0:8080"

	for i := 0; i < len(args); i++ {
		if args[i] == "--addr" {
			i++
			addr = args[i]
		}
	}

	if err := service.Start(addr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

// netu diff <file1.json> <file2.json> [--json]
func cmdDiff(args []string) {
	if len(args) < 2 {
		printCommandHelp("diff")
		os.Exit(1)
	}

	file1 := args[0]
	file2 := args[1]
	jsonOut := hasFlag(args, "--json")

	result, err := diff.CompareFiles(file1, file2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	if jsonOut {
		printJSON(result)
		writeOutput(args, result)
		return
	}

	fmt.Printf("Diff: %s vs %s\n\n", file1, file2)
	if len(result.Changes) == 0 {
		fmt.Println("  No differences found.")
		return
	}

	for _, c := range result.Changes {
		switch c.Type {
		case "added":
			fmt.Printf("  %s %s: %s\n", output.Green("+"), c.Key, c.New)
		case "removed":
			fmt.Printf("  %s %s: %s\n", output.Red("-"), c.Key, c.Old)
		case "changed":
			fmt.Printf("  %s %s:\n", output.Yellow("~"), c.Key)
			fmt.Printf("      old: %s\n", c.Old)
			fmt.Printf("      new: %s\n", c.New)
		}
	}
	fmt.Printf("\n%d change(s)\n", len(result.Changes))
}

func printUsage() {
	fmt.Println(`netu — lightweight network toolkit

Usage:
  netu <command> [options]

Commands:
  scan     Scan a port or range of ports on a host
  check    Check specific ports on a host
  watch    Wait for a port to come up
  top      Scan the top 100 common ports on a host
  lookup   DNS lookup for a domain or IP
  http     Probe a URL for status, timing, headers, TLS, and security
  inspect  Full inspection of a host (DNS + ports + HTTP + TLS)
  cert     Inspect TLS certificate on a host
  monitor  Continuously monitor a port (UP/DOWN)
  banner   Grab service banner from a port
  ping     TCP ping a host with latency stats
  trace    Traceroute to a host (requires sudo)
  whois    WHOIS lookup for a domain or IP
  diff     Compare two JSON result files
  serve    Run netu as an HTTP API service
  help     Show help for a command

Global flags:
  --help, -h     Show help
  --json         Output results as JSON (supported on all commands)
  --output file  Write JSON results to a file

Run 'netu help <command>' for details on a specific command.`)
}
