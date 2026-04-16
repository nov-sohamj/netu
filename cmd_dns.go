package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"netu/lookup"
	"netu/output"
	"netu/whois"
)

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
