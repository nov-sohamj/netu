package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

type CertInfo struct {
	Subject  string   `json:"subject"`
	Issuer   string   `json:"issuer"`
	SANs     []string `json:"sans"`
	NotBefore string  `json:"not_before"`
	NotAfter  string  `json:"not_after"`
	DaysLeft  int     `json:"days_left"`
	Serial    string  `json:"serial"`
	SigAlgo   string  `json:"signature_algorithm"`
	KeyUsage  []string `json:"key_usage,omitempty"`
	IsCA      bool    `json:"is_ca"`
}

type Result struct {
	Host  string     `json:"host"`
	Port  int        `json:"port"`
	Chain []CertInfo `json:"chain"`
}

// Inspect connects to host:port via TLS and inspects the certificate chain.
func Inspect(host string, port int, timeout time.Duration) (Result, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: timeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: host,
	})
	if err != nil {
		// Retry without verification to still show cert info for self-signed
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:        host,
		})
		if err != nil {
			return Result{}, fmt.Errorf("TLS connect failed: %w", err)
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return Result{}, fmt.Errorf("no certificates presented by %s", addr)
	}

	var chain []CertInfo
	for _, c := range state.PeerCertificates {
		info := CertInfo{
			Subject:   c.Subject.CommonName,
			Issuer:    c.Issuer.CommonName,
			NotBefore: c.NotBefore.Format("2006-01-02"),
			NotAfter:  c.NotAfter.Format("2006-01-02"),
			DaysLeft:  int(time.Until(c.NotAfter).Hours() / 24),
			Serial:    c.SerialNumber.Text(16),
			SigAlgo:   c.SignatureAlgorithm.String(),
			IsCA:      c.IsCA,
		}

		for _, dns := range c.DNSNames {
			info.SANs = append(info.SANs, dns)
		}
		for _, ip := range c.IPAddresses {
			info.SANs = append(info.SANs, ip.String())
		}

		info.KeyUsage = decodeKeyUsage(c.KeyUsage, c.ExtKeyUsage)
		chain = append(chain, info)
	}

	return Result{
		Host:  host,
		Port:  port,
		Chain: chain,
	}, nil
}

func decodeKeyUsage(ku x509.KeyUsage, eku []x509.ExtKeyUsage) []string {
	var usages []string

	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}

	for _, e := range eku {
		switch e {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Auth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Auth")
		}
	}

	return usages
}
