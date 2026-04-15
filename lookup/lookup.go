package lookup

import (
	"fmt"
	"net"
	"strings"
)

type Result struct {
	Type    string
	Records []string
}

// Forward resolves a domain to its A (IPv4) records.
func Forward(host string) (Result, error) {
	ips, err := net.LookupHost(host)
	if err != nil {
		return Result{}, fmt.Errorf("lookup failed: %w", err)
	}
	return Result{Type: "A/AAAA", Records: ips}, nil
}

// Reverse resolves an IP address to hostnames.
func Reverse(ip string) (Result, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return Result{}, fmt.Errorf("reverse lookup failed: %w", err)
	}
	// Trim trailing dots from hostnames
	for i, n := range names {
		names[i] = strings.TrimSuffix(n, ".")
	}
	return Result{Type: "PTR", Records: names}, nil
}

// QueryA returns IPv4 addresses for a domain.
func QueryA(host string) (Result, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return Result{}, fmt.Errorf("A lookup failed: %w", err)
	}
	var records []string
	for _, ip := range ips {
		if ip.To4() != nil {
			records = append(records, ip.String())
		}
	}
	if len(records) == 0 {
		return Result{Type: "A", Records: nil}, fmt.Errorf("no A records found for %s", host)
	}
	return Result{Type: "A", Records: records}, nil
}

// QueryAAAA returns IPv6 addresses for a domain.
func QueryAAAA(host string) (Result, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return Result{}, fmt.Errorf("AAAA lookup failed: %w", err)
	}
	var records []string
	for _, ip := range ips {
		if ip.To4() == nil {
			records = append(records, ip.String())
		}
	}
	if len(records) == 0 {
		return Result{Type: "AAAA", Records: nil}, fmt.Errorf("no AAAA records found for %s", host)
	}
	return Result{Type: "AAAA", Records: records}, nil
}

// QueryMX returns mail exchange records for a domain.
func QueryMX(host string) (Result, error) {
	mxs, err := net.LookupMX(host)
	if err != nil {
		return Result{}, fmt.Errorf("MX lookup failed: %w", err)
	}
	var records []string
	for _, mx := range mxs {
		records = append(records, fmt.Sprintf("%s (priority %d)", strings.TrimSuffix(mx.Host, "."), mx.Pref))
	}
	return Result{Type: "MX", Records: records}, nil
}

// QueryNS returns name server records for a domain.
func QueryNS(host string) (Result, error) {
	nss, err := net.LookupNS(host)
	if err != nil {
		return Result{}, fmt.Errorf("NS lookup failed: %w", err)
	}
	var records []string
	for _, ns := range nss {
		records = append(records, strings.TrimSuffix(ns.Host, "."))
	}
	return Result{Type: "NS", Records: records}, nil
}

// QueryTXT returns TXT records for a domain.
func QueryTXT(host string) (Result, error) {
	txts, err := net.LookupTXT(host)
	if err != nil {
		return Result{}, fmt.Errorf("TXT lookup failed: %w", err)
	}
	return Result{Type: "TXT", Records: txts}, nil
}

// QueryCNAME returns the canonical name for a domain.
func QueryCNAME(host string) (Result, error) {
	cname, err := net.LookupCNAME(host)
	if err != nil {
		return Result{}, fmt.Errorf("CNAME lookup failed: %w", err)
	}
	cname = strings.TrimSuffix(cname, ".")
	return Result{Type: "CNAME", Records: []string{cname}}, nil
}

// IsIP returns true if the input looks like an IP address.
func IsIP(s string) bool {
	return net.ParseIP(s) != nil
}
