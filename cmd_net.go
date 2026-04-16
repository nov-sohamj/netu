package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"time"

	"netu/banner"
	"netu/monitor"
	"netu/output"
	"netu/ping"
	"netu/trace"
)

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
