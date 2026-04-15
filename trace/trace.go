package trace

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

type Hop struct {
	TTL  int    `json:"ttl"`
	Addr string `json:"addr"`
	Host string `json:"host"`
	RTT  string `json:"rtt"`
	OK   bool   `json:"ok"`
}

type Result struct {
	Target  string `json:"target"`
	MaxHops int    `json:"max_hops"`
	Hops    []Hop  `json:"hops"`
}

// Trace performs a traceroute to the target host by sending UDP packets
// with increasing TTL values and listening for ICMP responses.
// Requires root/sudo for raw socket access.
func Trace(target string, maxHops int, timeout time.Duration) (Result, error) {
	// Resolve the target
	ips, err := net.LookupHost(target)
	if err != nil {
		return Result{}, fmt.Errorf("resolve failed: %w", err)
	}
	destIP := net.ParseIP(ips[0])
	if destIP == nil {
		return Result{}, fmt.Errorf("invalid IP: %s", ips[0])
	}

	dest := destIP.To4()
	if dest == nil {
		return Result{}, fmt.Errorf("IPv6 not supported, got: %s", ips[0])
	}

	result := Result{
		Target:  fmt.Sprintf("%s (%s)", target, dest.String()),
		MaxHops: maxHops,
	}

	for ttl := 1; ttl <= maxHops; ttl++ {
		hop := traceHop(dest, ttl, timeout)
		result.Hops = append(result.Hops, hop)

		// Reached destination
		if hop.OK && hop.Addr == dest.String() {
			break
		}
	}

	return result, nil
}

func traceHop(dest net.IP, ttl int, timeout time.Duration) Hop {
	// Create a raw ICMP socket to receive responses
	recvSock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return Hop{TTL: ttl, Addr: "*", Host: "*", RTT: "-", OK: false}
	}
	defer syscall.Close(recvSock)

	// Create a UDP socket to send probes
	sendSock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return Hop{TTL: ttl, Addr: "*", Host: "*", RTT: "-", OK: false}
	}
	defer syscall.Close(sendSock)

	// Set TTL on the send socket
	syscall.SetsockoptInt(sendSock, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)

	// Set receive timeout
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	syscall.SetsockoptTimeval(recvSock, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Bind the receive socket
	syscall.Bind(recvSock, &syscall.SockaddrInet4{Port: 0, Addr: [4]byte{0, 0, 0, 0}})

	// Send UDP packet to destination on a high port
	destAddr := &syscall.SockaddrInet4{Port: 33434 + ttl, Addr: [4]byte{dest[0], dest[1], dest[2], dest[3]}}

	start := time.Now()
	syscall.Sendto(sendSock, []byte{0}, 0, destAddr)

	// Receive ICMP response
	buf := make([]byte, 512)
	_, from, err := syscall.Recvfrom(recvSock, buf, 0)
	rtt := time.Since(start)

	if err != nil {
		return Hop{TTL: ttl, Addr: "*", Host: "*", RTT: "-", OK: false}
	}

	fromAddr, ok := from.(*syscall.SockaddrInet4)
	if !ok {
		return Hop{TTL: ttl, Addr: "*", Host: "*", RTT: "-", OK: false}
	}

	ip := fmt.Sprintf("%d.%d.%d.%d", fromAddr.Addr[0], fromAddr.Addr[1], fromAddr.Addr[2], fromAddr.Addr[3])

	// Reverse lookup the hop
	host := ip
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		host = names[0]
		if host[len(host)-1] == '.' {
			host = host[:len(host)-1]
		}
	}

	return Hop{
		TTL:  ttl,
		Addr: ip,
		Host: host,
		RTT:  rtt.Round(time.Microsecond).String(),
		OK:   true,
	}
}
