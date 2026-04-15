package inspect

import (
	"time"

	"netu/cert"
	"netu/lookup"
	"netu/probe"
	"netu/scanner"
)

type Result struct {
	Host    string            `json:"host"`
	DNS     *DNSResult        `json:"dns,omitempty"`
	Ports   *PortResult       `json:"ports,omitempty"`
	HTTP    *probe.Result     `json:"http,omitempty"`
	TLS     *cert.Result      `json:"tls,omitempty"`
	Errors  []string          `json:"errors,omitempty"`
}

type DNSResult struct {
	IPs []string `json:"ips"`
	NS  []string `json:"ns,omitempty"`
	MX  []string `json:"mx,omitempty"`
}

type PortResult struct {
	Open  []scanner.Result `json:"open"`
	Total int              `json:"total"`
}

// Run performs a comprehensive inspection of a host:
// DNS lookup, top port scan, HTTP probe, and TLS cert inspection.
func Run(host string) Result {
	result := Result{Host: host}

	// 1. DNS lookup
	dns := &DNSResult{}
	fwd, err := lookup.Forward(host)
	if err != nil {
		result.Errors = append(result.Errors, "DNS: "+err.Error())
	} else {
		dns.IPs = fwd.Records
	}

	ns, err := lookup.QueryNS(host)
	if err == nil {
		dns.NS = ns.Records
	}

	mx, err := lookup.QueryMX(host)
	if err == nil {
		mx.Records = mx.Records
		dns.MX = mx.Records
	}

	if len(dns.IPs) > 0 || len(dns.NS) > 0 {
		result.DNS = dns
	}

	// 2. Port scan (top 100)
	opts := scanner.ScanOptions{
		Timeout: 2 * time.Second,
		Workers: 100,
	}
	portResults := scanner.CheckPorts(host, scanner.Top100, opts)
	var openPorts []scanner.Result
	for _, r := range portResults {
		if r.Open {
			openPorts = append(openPorts, r)
		}
	}
	result.Ports = &PortResult{
		Open:  openPorts,
		Total: len(scanner.Top100),
	}

	// 3. HTTP probe (try https first, fall back to http)
	httpResult, err := probe.HTTP("https://"+host, 10*time.Second)
	if err != nil {
		httpResult, err = probe.HTTP("http://"+host, 10*time.Second)
		if err != nil {
			result.Errors = append(result.Errors, "HTTP: "+err.Error())
		} else {
			result.HTTP = &httpResult
		}
	} else {
		result.HTTP = &httpResult
	}

	// 4. TLS cert inspection
	certResult, err := cert.Inspect(host, 443, 5*time.Second)
	if err != nil {
		result.Errors = append(result.Errors, "TLS: "+err.Error())
	} else {
		result.TLS = &certResult
	}

	return result
}
