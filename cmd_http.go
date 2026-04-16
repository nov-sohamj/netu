package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"netu/output"
	"netu/probe"
)

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
