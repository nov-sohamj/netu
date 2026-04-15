package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"pscan/lookup"
	"pscan/scanner"
	"pscan/service"
)

const defaultTimeout = 2 * time.Second
const defaultWorkers = 100

var helpTexts = map[string]string{
	"scan": `pscan scan — scan a port or range of ports on a host

Usage:
  pscan scan <host> <port|start-end> [options]

Options:
  --timeout duration   Connection timeout per port (default: 2s)
  --workers n          Number of concurrent goroutines (default: 100)

Examples:
  pscan scan localhost 80
  pscan scan localhost 1-1024
  pscan scan 192.168.1.1 20-100 --timeout 5s --workers 200`,

	"check": `pscan check — check specific ports on a host

Usage:
  pscan check <host> <port> [port...] [options]

Options:
  --timeout duration   Connection timeout per port (default: 2s)

Examples:
  pscan check localhost 22 80 443
  pscan check 192.168.1.1 3306 5432 --timeout 5s`,

	"watch": `pscan watch — wait for a port to come up

Usage:
  pscan watch <host> <port> [options]

Options:
  --timeout duration    How long to wait overall (default: 30s)
  --interval duration   How often to retry (default: 1s)

Examples:
  pscan watch localhost 5432 --timeout 60s
  pscan watch localhost 8080 --interval 2s`,

	"lookup": `pscan lookup — DNS lookup for a domain or IP

Usage:
  pscan lookup <domain|ip> [options]

Options:
  --type type   Record type: a, aaaa, mx, ns, txt, cname (default: auto-detect)

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
  pscan lookup google.com
  pscan lookup google.com --type mx
  pscan lookup google.com --type ns
  pscan lookup 8.8.8.8`,

	"serve": `pscan serve — run pscan as an HTTP API service

Usage:
  pscan serve [options]

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
  pscan serve
  pscan serve --addr 127.0.0.1:9090`,
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	// handle --help / -h anywhere
	if cmd == "--help" || cmd == "-h" {
		printUsage()
		return
	}

	// handle: pscan help [command]
	if cmd == "help" {
		if len(os.Args) < 3 {
			printUsage()
			return
		}
		printCommandHelp(os.Args[2])
		return
	}

	// handle: pscan <command> --help
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

// pscan scan <host> <port|start-end> [--timeout duration] [--workers n]
func cmdScan(args []string) {
	if len(args) < 2 {
		printCommandHelp("scan")
		os.Exit(1)
	}

	host := args[0]
	timeout := defaultTimeout
	workers := defaultWorkers

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

	fmt.Printf("Scanning %s ports %d-%d ...\n\n", host, startPort, endPort)
	results := scanner.ScanPorts(host, startPort, endPort, timeout, workers)

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

// pscan check <host> <port> [port...] [--timeout duration]
func cmdCheck(args []string) {
	if len(args) < 2 {
		printCommandHelp("check")
		os.Exit(1)
	}

	host := args[0]
	timeout := defaultTimeout
	var ports []int

	for i := 1; i < len(args); i++ {
		if args[i] == "--timeout" {
			i++
			var err error
			timeout, err = time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid timeout: %s\n", args[i])
				os.Exit(1)
			}
			continue
		}
		p, err := strconv.Atoi(args[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid port: %s\n", args[i])
			os.Exit(1)
		}
		ports = append(ports, p)
	}

	fmt.Printf("Checking %d port(s) on %s ...\n\n", len(ports), host)
	results := scanner.CheckPorts(host, ports, timeout)

	for _, r := range results {
		state := "closed"
		if r.Open {
			state = "open"
		}
		fmt.Printf("  %-6d %s\n", r.Port, state)
	}
}

// pscan watch <host> <port> [--timeout duration] [--interval duration]
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

	fmt.Printf("Watching %s:%d (timeout %s, poll every %s) ...\n", host, port, timeout, interval)
	result := scanner.WatchPort(host, port, timeout, interval)

	if result.Up {
		fmt.Printf("Port %d is UP (took %s)\n", port, result.Elapsed.Round(time.Millisecond))
	} else {
		fmt.Printf("Timed out after %s — port %d did not open.\n", result.Elapsed.Round(time.Millisecond), port)
		os.Exit(1)
	}
}

// pscan lookup <domain|ip> [--type a|aaaa|mx|ns|txt|cname]
func cmdLookup(args []string) {
	if len(args) < 1 {
		printCommandHelp("lookup")
		os.Exit(1)
	}

	target := args[0]
	recordType := ""

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

	fmt.Printf("Lookup: %s [%s]\n\n", target, result.Type)
	for _, r := range result.Records {
		fmt.Printf("  %s\n", r)
	}
}

// pscan serve [--addr address]
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
	fmt.Println(`pscan — lightweight network toolkit

Usage:
  pscan <command> [options]

Commands:
  scan     Scan a port or range of ports on a host
  check    Check specific ports on a host
  watch    Wait for a port to come up
  lookup   DNS lookup for a domain or IP
  serve    Run pscan as an HTTP API service
  help     Show help for a command

Flags:
  --help, -h   Show help

Run 'pscan help <command>' for details on a specific command.`)
}
