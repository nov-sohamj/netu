package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"netu/cert"
	"netu/inspect"
	"netu/output"
)

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
