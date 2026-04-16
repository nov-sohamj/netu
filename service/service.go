package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netu/lookup"
	"netu/scanner"
)

// --- Stats ---

type serverStats struct {
	startTime time.Time
	requests  atomic.Int64
}

var stats = &serverStats{}

func statsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stats.requests.Add(1)
		next.ServeHTTP(w, r)
	})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, apiResponse{
		Status: "ok",
		Data: map[string]interface{}{
			"uptime":     time.Since(stats.startTime).Round(time.Second).String(),
			"requests":   stats.requests.Load(),
			"dns_cached": lookup.CacheSize(),
		},
	})
}

// --- Rate Limiter ---

type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     int           // max requests per window
	window   time.Duration // time window
}

type visitor struct {
	count   int
	resetAt time.Time
}

func newRateLimiter(rate int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
	}
	// Clean up stale entries periodically
	go func() {
		for {
			time.Sleep(window)
			rl.mu.Lock()
			now := time.Now()
			for ip, v := range rl.visitors {
				if now.After(v.resetAt) {
					delete(rl.visitors, ip)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, exists := rl.visitors[ip]
	if !exists || now.After(v.resetAt) {
		rl.visitors[ip] = &visitor{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	v.count++
	return v.count <= rl.rate
}

// --- Middleware ---

func rateLimitMiddleware(rl *rateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		if !rl.allow(ip) {
			writeJSON(w, http.StatusTooManyRequests, apiResponse{
				Status: "error",
				Error:  "rate limit exceeded, try again later",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func apiKeyMiddleware(key string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health endpoint is always open
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		provided := r.Header.Get("X-API-Key")
		if provided == "" {
			provided = r.URL.Query().Get("key")
		}
		if provided != key {
			writeJSON(w, http.StatusUnauthorized, apiResponse{
				Status: "error",
				Error:  "invalid or missing API key",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s %s", r.RemoteAddr, r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

// --- Validation helpers ---

func validateHost(host string) bool {
	if host == "" {
		return false
	}
	if len(host) > 253 {
		return false
	}
	// Block obvious bad inputs
	if strings.ContainsAny(host, " \t\n\r;|&$`") {
		return false
	}
	return true
}

func validatePort(p int) bool {
	return p >= 1 && p <= 65535
}

type apiResponse struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, resp apiResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	portsParam := r.URL.Query().Get("ports")
	if host == "" || portsParam == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "host and ports are required (e.g. ?host=localhost&ports=1-1024)"})
		return
	}
	if !validateHost(host) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "invalid host"})
		return
	}

	var startPort, endPort int
	parts := strings.SplitN(portsParam, "-", 2)
	if len(parts) == 1 {
		p, err := strconv.Atoi(parts[0])
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "invalid port: " + parts[0]})
			return
		}
		startPort, endPort = p, p
	} else {
		var err error
		startPort, err = strconv.Atoi(parts[0])
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "invalid start port: " + parts[0]})
			return
		}
		endPort, err = strconv.Atoi(parts[1])
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "invalid end port: " + parts[1]})
			return
		}
	}

	if !validatePort(startPort) || !validatePort(endPort) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "ports must be between 1 and 65535"})
		return
	}
	if endPort-startPort > 10000 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "port range too large (max 10000)"})
		return
	}

	timeout := 2 * time.Second
	if t := r.URL.Query().Get("timeout"); t != "" {
		parsed, err := time.ParseDuration(t)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "invalid timeout: " + t})
			return
		}
		if parsed > 30*time.Second {
			parsed = 30 * time.Second
		}
		timeout = parsed
	}

	workers := 100
	if w2 := r.URL.Query().Get("workers"); w2 != "" {
		parsed, err := strconv.Atoi(w2)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "invalid workers: " + w2})
			return
		}
		if parsed > 500 {
			parsed = 500
		}
		workers = parsed
	}

	opts := scanner.ScanOptions{Timeout: timeout, Workers: workers}
	results := scanner.ScanPorts(host, startPort, endPort, opts)
	writeJSON(w, http.StatusOK, apiResponse{Status: "ok", Data: results})
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	portsParam := r.URL.Query().Get("ports")
	if host == "" || portsParam == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "host and ports are required (e.g. ?host=localhost&ports=22,80,443)"})
		return
	}
	if !validateHost(host) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "invalid host"})
		return
	}

	var ports []int
	for _, s := range strings.Split(portsParam, ",") {
		p, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "invalid port: " + s})
			return
		}
		if !validatePort(p) {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "port out of range: " + s})
			return
		}
		ports = append(ports, p)
	}

	if len(ports) > 100 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "too many ports (max 100)"})
		return
	}

	timeout := 2 * time.Second
	if t := r.URL.Query().Get("timeout"); t != "" {
		parsed, err := time.ParseDuration(t)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "invalid timeout: " + t})
			return
		}
		if parsed > 30*time.Second {
			parsed = 30 * time.Second
		}
		timeout = parsed
	}

	opts := scanner.ScanOptions{Timeout: timeout, Workers: 100}
	results := scanner.CheckPorts(host, ports, opts)
	writeJSON(w, http.StatusOK, apiResponse{Status: "ok", Data: results})
}

func handleLookup(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "target is required (e.g. ?target=google.com)"})
		return
	}
	if !validateHost(target) && !lookup.IsIP(target) {
		writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "invalid target"})
		return
	}

	recordType := strings.ToLower(r.URL.Query().Get("type"))

	if lookup.IsIP(target) && recordType == "" {
		recordType = "ptr"
	}

	var result lookup.Result
	var err error

	switch recordType {
	case "ptr":
		result, err = lookup.CachedReverse(target)
	case "a":
		result, err = lookup.QueryA(target)
	case "aaaa":
		result, err = lookup.QueryAAAA(target)
	case "mx":
		result, err = lookup.QueryMX(target)
	case "ns":
		result, err = lookup.QueryNS(target)
	case "txt":
		result, err = lookup.QueryTXT(target)
	case "cname":
		result, err = lookup.QueryCNAME(target)
	default:
		result, err = lookup.CachedForward(target)
	}

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Status: "error", Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Status: "ok", Data: result})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, apiResponse{Status: "ok", Data: "netu service is running"})
}

// Start launches the HTTP API server on the given address.
func Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/stats", handleStats)
	mux.HandleFunc("/scan", handleScan)
	mux.HandleFunc("/check", handleCheck)
	mux.HandleFunc("/lookup", handleLookup)

	// Verify the address is valid before starting
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}

	// Build middleware chain
	var handler http.Handler = mux

	// Stats tracking
	stats.startTime = time.Now()
	handler = statsMiddleware(handler)

	// Rate limiting: 60 requests per minute per IP
	rl := newRateLimiter(60, time.Minute)
	handler = rateLimitMiddleware(rl, handler)

	// API key auth (optional — only if NETU_API_KEY is set)
	if apiKey := os.Getenv("NETU_API_KEY"); apiKey != "" {
		handler = apiKeyMiddleware(apiKey, handler)
		log.Printf("API key authentication enabled")
	}

	// Request logging
	handler = loggingMiddleware(handler)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	log.Printf("netu service starting on %s:%s", host, port)
	log.Printf("endpoints: /health, /stats, /scan, /check, /lookup")
	log.Printf("rate limit: 60 req/min per IP")

	// Graceful shutdown on SIGINT/SIGTERM
	done := make(chan error, 1)
	go func() {
		done <- srv.ListenAndServe()
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	select {
	case err := <-done:
		return err
	case <-sig:
		log.Printf("shutting down gracefully...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}
