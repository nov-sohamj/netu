package probe

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type TLSInfo struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	DaysLeft  int    `json:"days_left"`
	Version   string `json:"version"`
}

type Header struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type SecurityCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass", "warn", "fail"
	Detail string `json:"detail"`
}

type Result struct {
	URL            string          `json:"url"`
	Status         int             `json:"status"`
	StatusText     string          `json:"status_text"`
	ResponseTime   string          `json:"response_time"`
	ContentLen     int64           `json:"content_length"`
	Headers        []Header        `json:"headers"`
	TLS            *TLSInfo        `json:"tls,omitempty"`
	SecurityChecks []SecurityCheck `json:"security_checks,omitempty"`
}

// HTTP probes a URL and returns status, timing, headers, TLS info, and security checks.
func HTTP(url string, timeout time.Duration) (Result, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
		// Don't follow redirects — report actual response
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Smart default: auto-add https if no scheme
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	start := time.Now()
	resp, err := client.Get(url)
	elapsed := time.Since(start)
	if err != nil {
		return Result{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	contentLen := int64(len(body))
	if resp.ContentLength > 0 {
		contentLen = resp.ContentLength
	}

	var headers []Header
	for k, vals := range resp.Header {
		for _, v := range vals {
			headers = append(headers, Header{Key: k, Value: v})
		}
	}

	result := Result{
		URL:          url,
		Status:       resp.StatusCode,
		StatusText:   resp.Status,
		ResponseTime: elapsed.Round(time.Millisecond).String(),
		ContentLen:   contentLen,
		Headers:      headers,
	}

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		result.TLS = &TLSInfo{
			Subject:   cert.Subject.CommonName,
			Issuer:    cert.Issuer.CommonName,
			NotBefore: cert.NotBefore.Format("2006-01-02"),
			NotAfter:  cert.NotAfter.Format("2006-01-02"),
			DaysLeft:  daysLeft,
			Version:   tlsVersionString(resp.TLS.Version),
		}
	}

	// Run security checks
	result.SecurityChecks = runSecurityChecks(resp, result.TLS)

	return result, nil
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

func runSecurityChecks(resp *http.Response, tlsInfo *TLSInfo) []SecurityCheck {
	var checks []SecurityCheck

	// TLS version check
	if tlsInfo != nil {
		switch tlsInfo.Version {
		case "TLS 1.3":
			checks = append(checks, SecurityCheck{Name: "TLS Version", Status: "pass", Detail: "TLS 1.3"})
		case "TLS 1.2":
			checks = append(checks, SecurityCheck{Name: "TLS Version", Status: "pass", Detail: "TLS 1.2"})
		case "TLS 1.1":
			checks = append(checks, SecurityCheck{Name: "TLS Version", Status: "warn", Detail: "TLS 1.1 — deprecated"})
		case "TLS 1.0":
			checks = append(checks, SecurityCheck{Name: "TLS Version", Status: "fail", Detail: "TLS 1.0 — insecure"})
		}

		// Certificate expiry
		if tlsInfo.DaysLeft < 0 {
			checks = append(checks, SecurityCheck{Name: "Certificate Expiry", Status: "fail", Detail: "certificate has expired"})
		} else if tlsInfo.DaysLeft < 14 {
			checks = append(checks, SecurityCheck{Name: "Certificate Expiry", Status: "warn", Detail: fmt.Sprintf("expires in %d days", tlsInfo.DaysLeft)})
		} else {
			checks = append(checks, SecurityCheck{Name: "Certificate Expiry", Status: "pass", Detail: fmt.Sprintf("%d days remaining", tlsInfo.DaysLeft)})
		}
	}

	// HTTP security headers
	headerChecks := []struct {
		header string
		name   string
	}{
		{"Strict-Transport-Security", "HSTS"},
		{"X-Content-Type-Options", "X-Content-Type-Options"},
		{"X-Frame-Options", "X-Frame-Options"},
		{"X-Xss-Protection", "X-XSS-Protection"},
		{"Content-Security-Policy", "Content-Security-Policy"},
		{"Referrer-Policy", "Referrer-Policy"},
	}

	for _, hc := range headerChecks {
		val := resp.Header.Get(hc.header)
		if val != "" {
			checks = append(checks, SecurityCheck{Name: hc.name, Status: "pass", Detail: val})
		} else {
			checks = append(checks, SecurityCheck{Name: hc.name, Status: "warn", Detail: "missing"})
		}
	}

	return checks
}
