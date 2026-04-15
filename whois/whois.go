package whois

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type Result struct {
	Target string `json:"target"`
	Server string `json:"server"`
	Raw    string `json:"raw"`
}

var tldServers = map[string]string{
	"com":  "whois.verisign-grs.com",
	"net":  "whois.verisign-grs.com",
	"org":  "whois.pir.org",
	"info": "whois.afilias.net",
	"io":   "whois.nic.io",
	"co":   "whois.nic.co",
	"dev":  "whois.nic.google",
	"app":  "whois.nic.google",
	"me":   "whois.nic.me",
	"ai":   "whois.nic.ai",
	"xyz":  "whois.nic.xyz",
	"uk":   "whois.nic.uk",
	"de":   "whois.denic.de",
	"fr":   "whois.nic.fr",
	"in":   "whois.registry.in",
}

// Lookup performs a WHOIS query for the given domain or IP.
func Lookup(target string, timeout time.Duration) (Result, error) {
	server := resolveServer(target)

	conn, err := net.DialTimeout("tcp", server+":43", timeout)
	if err != nil {
		return Result{}, fmt.Errorf("connect to %s failed: %w", server, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// Send query
	fmt.Fprintf(conn, "%s\r\n", target)

	// Read response
	data, err := io.ReadAll(conn)
	if err != nil {
		return Result{}, fmt.Errorf("read failed: %w", err)
	}

	return Result{
		Target: target,
		Server: server,
		Raw:    string(data),
	}, nil
}

func resolveServer(target string) string {
	// Check if it's an IP address
	if net.ParseIP(target) != nil {
		return "whois.arin.net"
	}

	// Extract TLD
	parts := strings.Split(target, ".")
	if len(parts) >= 2 {
		tld := parts[len(parts)-1]
		if server, ok := tldServers[tld]; ok {
			return server
		}
	}

	return "whois.iana.org"
}
