package ping

import (
	"fmt"
	"math"
	"net"
	"time"
)

type Stats struct {
	Host       string        `json:"host"`
	Sent       int           `json:"sent"`
	Received   int           `json:"received"`
	Lost       int           `json:"lost"`
	LossPercent float64      `json:"loss_percent"`
	MinRTT     string        `json:"min_rtt"`
	AvgRTT     string        `json:"avg_rtt"`
	MaxRTT     string        `json:"max_rtt"`
	Pings      []PingResult  `json:"pings"`
}

type PingResult struct {
	Seq  int    `json:"seq"`
	RTT  string `json:"rtt"`
	OK   bool   `json:"ok"`
}

// TCPPing performs a TCP-based ping to host:port.
// Uses TCP connect since ICMP requires root privileges.
func TCPPing(host string, port int, count int, timeout time.Duration) Stats {
	addr := fmt.Sprintf("%s:%d", host, port)

	var pings []PingResult
	var rtts []time.Duration
	received := 0

	for i := 1; i <= count; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, timeout)
		rtt := time.Since(start)

		if err != nil {
			pings = append(pings, PingResult{Seq: i, RTT: "-", OK: false})
		} else {
			conn.Close()
			received++
			rtts = append(rtts, rtt)
			pings = append(pings, PingResult{
				Seq: i,
				RTT: rtt.Round(time.Microsecond).String(),
				OK:  true,
			})
		}

		// Wait between pings (except after the last one)
		if i < count {
			time.Sleep(500 * time.Millisecond)
		}
	}

	lost := count - received
	lossPct := float64(lost) / float64(count) * 100

	stats := Stats{
		Host:        addr,
		Sent:        count,
		Received:    received,
		Lost:        lost,
		LossPercent: math.Round(lossPct*10) / 10,
		MinRTT:      "-",
		AvgRTT:      "-",
		MaxRTT:      "-",
		Pings:       pings,
	}

	if len(rtts) > 0 {
		minRTT, maxRTT := rtts[0], rtts[0]
		var total time.Duration
		for _, r := range rtts {
			total += r
			if r < minRTT {
				minRTT = r
			}
			if r > maxRTT {
				maxRTT = r
			}
		}
		avgRTT := total / time.Duration(len(rtts))
		stats.MinRTT = minRTT.Round(time.Microsecond).String()
		stats.AvgRTT = avgRTT.Round(time.Microsecond).String()
		stats.MaxRTT = maxRTT.Round(time.Microsecond).String()
	}

	return stats
}
