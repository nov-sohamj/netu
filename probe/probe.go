package probe

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

type TLSInfo struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	DaysLeft  int    `json:"days_left"`
}

type Header struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Result struct {
	URL          string  `json:"url"`
	Status       int     `json:"status"`
	StatusText   string  `json:"status_text"`
	ResponseTime string  `json:"response_time"`
	ContentLen   int64   `json:"content_length"`
	Headers      []Header `json:"headers"`
	TLS          *TLSInfo `json:"tls,omitempty"`
}

// HTTP probes a URL and returns status, timing, headers, and TLS info.
func HTTP(url string, timeout time.Duration) (Result, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	start := time.Now()
	resp, err := client.Get(url)
	elapsed := time.Since(start)
	if err != nil {
		return Result{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read body to get content length if not set
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
		}
	}

	return result, nil
}
