package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

type Result struct {
	Port  int
	Open  bool
}

type WatchResult struct {
	Up       bool
	Elapsed  time.Duration
}

// ScanPorts scans a range of ports on a host concurrently.
func ScanPorts(host string, startPort, endPort int, timeout time.Duration, workers int) []Result {
	ports := make(chan int, workers)
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				open := isOpen(host, port, timeout)
				mu.Lock()
				results = append(results, Result{Port: port, Open: open})
				mu.Unlock()
			}
		}()
	}

	for p := startPort; p <= endPort; p++ {
		ports <- p
	}
	close(ports)
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	return results
}

// CheckPorts checks a specific set of ports on a host.
func CheckPorts(host string, ports []int, timeout time.Duration) []Result {
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			open := isOpen(host, p, timeout)
			mu.Lock()
			results = append(results, Result{Port: p, Open: open})
			mu.Unlock()
		}(port)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	return results
}

// WatchPort polls a port until it opens or the timeout expires.
// interval is how often to retry; timeout is the overall deadline.
func WatchPort(host string, port int, timeout, interval time.Duration) WatchResult {
	deadline := time.After(timeout)
	start := time.Now()

	for {
		if isOpen(host, port, 1*time.Second) {
			return WatchResult{Up: true, Elapsed: time.Since(start)}
		}

		select {
		case <-deadline:
			return WatchResult{Up: false, Elapsed: time.Since(start)}
		case <-time.After(interval):
		}
	}
}

func isOpen(host string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
