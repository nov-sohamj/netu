package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"netu/output"
	"netu/scanner"
)

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
			i++
		}
	}

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
			i++
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
