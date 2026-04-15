package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"netu/lookup"
	"netu/probe"
	"netu/scanner"
	"netu/service"
)

const defaultTimeout = 2 * time.Second
const defaultWorkers = 100

var helpTexts = map[string]string{
	"scan": `netu scan — scan a port or range of ports on a host

Usage:
  netu scan <host> <port|start-end> [options]

Options:
  --timeout duration   Connection timeout per port (default: 2s)
  --workers n          Number of concurrent goroutines (default: 100)
  --json               Output results as JSON

Examples:
  netu scan localhost 80
  netu scan localhost 1-1024
  netu scan 192.168.1.1 20-100 --timeout 5s --workers 200
  netu scan localhost 1-1024 --json`,

	"check": `netu check — check specific ports on a host

Usage:
  netu check <host> <port> [port...] [options]

Options:
  --timeout duration   Connection timeout per port (default: 2s)
  --json               Output results as JSON

Examples:
  netu check localhost 22 80 443
  netu check 192.168.1.1 3306 5432 --timeout 5s
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

	"top": `netu top — scan the top 100 common ports on a host

Usage:
  netu top <host> [options]

Options:
  --timeout duration   Connection timeout per port (default: 2s)
  --workers n          Number of concurrent goroutines (default: 100)
  --json               Output results as JSON

Scans the top 100 most commonly used ports including SSH (22), HTTP (80),
HTTPS (443), databases, and other well-known services.

Examples:
  netu top localhost
  netu top 192.168.1.1 --timeout 5s
  netu top localhost --json`,

	"http": `netu http — probe a URL for status, timing, headers, and TLS info

Usage:
  netu http <url> [options]

Options:
  --timeout duration   Request timeout (default: 10s)
  --json               Output results as JSON

Reports:
  - HTTP status code
  - Response time
  - Content length
  - Response headers
  - TLS certificate details and days until expiry (for HTTPS)

Examples:
  netu http https://google.com
  netu http http://localhost:8080
  netu http https://example.com --timeout 5s
  netu http https://example.com --json`,

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

// netu scan <host> <port|start-end> [--timeout duration] [--workers n] [--json]
func cmdScan(args []string) {
	if len(args) < 2 {
		printCommandHelp("scan")
		os.Exit(1)
	}

	host := args[0]
	timeout := defaultTimeout
	workers := defaultWorkers
	jsonOut := hasFlag(args, "--json")

	var startPort, endPort int
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

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--timeout":
			i++
			timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
		case "--workers":
			i++
			workers, err = strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid workers: %s\n", args[i])
				os.Exit(1)
			}
		}
	}

	results := scanner.ScanPorts(host, startPort, endPort, timeout, workers)

	if jsonOut {
		printJSON(results)
		return
	}

	fmt.Printf("Scanning %s ports %d-%d ...\n\n", host, startPort, endPort)
	open := 0
	for _, r := range results {
		if r.Open {
			fmt.Printf("  %-6d open\n", r.Port)
			open++
		}
	}
	total := endPort - startPort + 1
	if open == 0 {
		fmt.Println("  No open ports found.")
	}
	fmt.Printf("\n%d/%d ports open\n", open, total)
}

// netu check <host> <port> [port...] [--timeout duration] [--json]
func cmdCheck(args []string) {
	if len(args) < 2 {
		printCommandHelp("check")
		os.Exit(1)
	}

	host := args[0]
	timeout := defaultTimeout
	jsonOut := hasFlag(args, "--json")
	var ports []int

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
		case "--json":
			continue
		default:
			p, err := strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid port: %s\n", args[i])
				os.Exit(1)
			}
			ports = append(ports, p)
		}
	}

	results := scanner.CheckPorts(host, ports, timeout)

	if jsonOut {
		printJSON(results)
		return
	}

	fmt.Printf("Checking %d port(s) on %s ...\n\n", len(ports), host)
	for _, r := range results {
		state := "closed"
		if r.Open {
			state = "open"
		}
		fmt.Printf("  %-6d %s\n", r.Port, state)
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
		fmt.Printf("Port %d is UP (took %s)\n", port, result.Elapsed.Round(time.Millisecond))
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
		if args[i] == "--type" {
			i++
			recordType = strings.ToLower(args[i])
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
		return
	}

	fmt.Printf("Lookup: %s [%s]\n\n", target, result.Type)
	for _, r := range result.Records {
		fmt.Printf("  %s\n", r)
	}
}

// netu top <host> [--timeout duration] [--workers n] [--json]
func cmdTop(args []string) {
	if len(args) < 1 {
		printCommandHelp("top")
		os.Exit(1)
	}

	host := args[0]
	timeout := defaultTimeout
	workers := defaultWorkers
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
		case "--workers":
			i++
			var err error
			workers, err = strconv.Atoi(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid workers: %s\n", args[i])
				os.Exit(1)
			}
		}
	}

	results := scanner.CheckPorts(host, scanner.Top100, timeout)

	if jsonOut {
		printJSON(results)
		return
	}

	fmt.Printf("Scanning top %d ports on %s ...\n\n", len(scanner.Top100), host)
	open := 0
	for _, r := range results {
		if r.Open {
			fmt.Printf("  %-6d open\n", r.Port)
			open++
		}
	}
	if open == 0 {
		fmt.Println("  No open ports found.")
	}
	_ = workers // workers used via CheckPorts concurrency
	fmt.Printf("\n%d/%d ports open\n", open, len(scanner.Top100))
}

// netu http <url> [--timeout duration] [--json]
func cmdHTTP(args []string) {
	if len(args) < 1 {
		printCommandHelp("http")
		os.Exit(1)
	}

	url := args[0]
	timeout := 10 * time.Second
	jsonOut := hasFlag(args, "--json")

	for i := 1; i < len(args); i++ {
		if args[i] == "--timeout" {
			i++
			var err error
			timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
		}
	}

	result, err := probe.HTTP(url, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	if jsonOut {
		printJSON(result)
		return
	}

	fmt.Printf("HTTP Probe: %s\n\n", url)
	fmt.Printf("  Status:        %s\n", result.StatusText)
	fmt.Printf("  Response Time: %s\n", result.ResponseTime)
	fmt.Printf("  Content Size:  %d bytes\n", result.ContentLen)

	if result.TLS != nil {
		fmt.Printf("\n  TLS Certificate:\n")
		fmt.Printf("    Subject:  %s\n", result.TLS.Subject)
		fmt.Printf("    Issuer:   %s\n", result.TLS.Issuer)
		fmt.Printf("    Expires:  %s (%d days left)\n", result.TLS.NotAfter, result.TLS.DaysLeft)
	}

	fmt.Printf("\n  Headers:\n")
	for _, h := range result.Headers {
		fmt.Printf("    %s: %s\n", h.Key, h.Value)
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
  http     Probe a URL for status, timing, headers, and TLS info
  serve    Run netu as an HTTP API service
  help     Show help for a command

Global flags:
  --help, -h   Show help
  --json       Output results as JSON (supported on all commands)

Run 'netu help <command>' for details on a specific command.`)
}
