package banner

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type Result struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
	Proto  string `json:"proto"`
}

// Grab connects to host:port and reads whatever the service sends.
// Some services (SSH, SMTP, FTP) send a banner on connect.
// For HTTP, we send a minimal request to get the server header.
func Grab(host string, port int, timeout time.Duration) (Result, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return Result{}, fmt.Errorf("connect failed: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// For HTTP ports, send a request to get a response
	if port == 80 || port == 8080 || port == 8000 || port == 8888 || port == 3000 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	} else if port == 443 || port == 8443 {
		// Can't do TLS with plain net.Dial — report that it's a TLS port
		return Result{
			Host:   host,
			Port:   port,
			Banner: "(TLS port — use 'netu http https://" + host + "' for details)",
			Proto:  "tls",
		}, nil
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n == 0 && err != nil {
		return Result{}, fmt.Errorf("no banner received: %w", err)
	}

	raw := string(buf[:n])
	proto := detectProto(raw, port)

	return Result{
		Host:   host,
		Port:   port,
		Banner: strings.TrimSpace(raw),
		Proto:  proto,
	}, nil
}

func detectProto(banner string, port int) string {
	b := strings.ToUpper(banner)
	switch {
	case strings.HasPrefix(b, "SSH-"):
		return "ssh"
	case strings.HasPrefix(b, "220"):
		if port == 21 {
			return "ftp"
		}
		return "smtp"
	case strings.HasPrefix(b, "+OK"):
		return "pop3"
	case strings.HasPrefix(b, "* OK"):
		return "imap"
	case strings.HasPrefix(b, "HTTP/"):
		return "http"
	case strings.Contains(b, "MYSQL"):
		return "mysql"
	case strings.Contains(b, "REDIS"):
		return "redis"
	case strings.Contains(b, "MONGO"):
		return "mongodb"
	default:
		return "unknown"
	}
}
