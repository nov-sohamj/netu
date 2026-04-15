package monitor

import (
	"fmt"
	"net"
	"time"
)

type Event struct {
	Time   string `json:"time"`
	Status string `json:"status"`
	RTT    string `json:"rtt,omitempty"`
}

// OnEvent is called when a status change or check occurs.
type OnEvent func(Event)

// Run continuously monitors host:port, calling onEvent on every status
// change (UP->DOWN or DOWN->UP) and periodically on each check.
// It runs until the stop channel is closed.
func Run(host string, port int, interval, timeout time.Duration, verbose bool, onEvent OnEvent, stop <-chan struct{}) {
	addr := fmt.Sprintf("%s:%d", host, port)
	lastUp := false
	first := true

	for {
		select {
		case <-stop:
			return
		default:
		}

		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, timeout)
		rtt := time.Since(start)

		now := time.Now().Format("15:04:05")
		up := err == nil
		if up {
			conn.Close()
		}

		// Report on status change or first check
		if first || up != lastUp {
			if up {
				onEvent(Event{
					Time:   now,
					Status: "UP",
					RTT:    rtt.Round(time.Microsecond).String(),
				})
			} else {
				onEvent(Event{
					Time:   now,
					Status: "DOWN",
				})
			}
			first = false
			lastUp = up
		} else if verbose {
			// In verbose mode, report every check
			if up {
				onEvent(Event{
					Time:   now,
					Status: "UP",
					RTT:    rtt.Round(time.Microsecond).String(),
				})
			} else {
				onEvent(Event{
					Time:   now,
					Status: "DOWN",
				})
			}
		}

		select {
		case <-stop:
			return
		case <-time.After(interval):
		}
	}
}
