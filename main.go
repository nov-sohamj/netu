package main

import (
	"fmt"
	"os"
	"time"
)

const defaultTimeout = 2 * time.Second
const defaultWorkers = 100

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
