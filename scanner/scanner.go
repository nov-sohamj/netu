package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

type Result struct {
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service,omitempty"`
}

type WatchResult struct {
	Up      bool
	Elapsed time.Duration
}

type ScanOptions struct {
	Timeout   time.Duration
	Workers   int
	Retries   int
	RateLimit time.Duration // delay between each connection attempt
}

func DefaultOptions() ScanOptions {
	return ScanOptions{
		Timeout:   2 * time.Second,
		Workers:   100,
		Retries:   0,
		RateLimit: 0,
	}
}

func FastOptions() ScanOptions {
	return ScanOptions{
		Timeout:   500 * time.Millisecond,
		Workers:   500,
		Retries:   0,
		RateLimit: 0,
	}
}

// ScanPorts scans a range of ports on a host concurrently.
func ScanPorts(host string, startPort, endPort int, opts ScanOptions) []Result {
	ports := make(chan int, opts.Workers)
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				if opts.RateLimit > 0 {
					time.Sleep(opts.RateLimit)
				}
				open := isOpenWithRetry(host, port, opts.Timeout, opts.Retries)
				r := Result{Port: port, Open: open}
				if open {
					r.Service = LookupService(port)
				}
				mu.Lock()
				results = append(results, r)
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
func CheckPorts(host string, ports []int, opts ScanOptions) []Result {
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, opts.Workers)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if opts.RateLimit > 0 {
				time.Sleep(opts.RateLimit)
			}
			open := isOpenWithRetry(host, p, opts.Timeout, opts.Retries)
			r := Result{Port: p, Open: open}
			if open {
				r.Service = LookupService(p)
			}
			mu.Lock()
			results = append(results, r)
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

func isOpenWithRetry(host string, port int, timeout time.Duration, retries int) bool {
	for attempt := 0; attempt <= retries; attempt++ {
		if isOpen(host, port, timeout) {
			return true
		}
	}
	return false
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
