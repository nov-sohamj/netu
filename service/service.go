package service

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netu/lookup"
	"netu/scanner"
)

type scanRequest struct {
	Host      string `json:"host"`
	StartPort int    `json:"start_port"`
	EndPort   int    `json:"end_port"`
	Timeout   string `json:"timeout"`
	Workers   int    `json:"workers"`
}

type checkRequest struct {
	Host    string `json:"host"`
	Ports   []int  `json:"ports"`
	Timeout string `json:"timeout"`
}

type lookupRequest struct {
	Target     string `json:"target"`
	RecordType string `json:"type"`
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

	timeout := 2 * time.Second
	if t := r.URL.Query().Get("timeout"); t != "" {
		parsed, err := time.ParseDuration(t)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "invalid timeout: " + t})
			return
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

	var ports []int
	for _, s := range strings.Split(portsParam, ",") {
		p, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "invalid port: " + s})
			return
		}
		ports = append(ports, p)
	}

	timeout := 2 * time.Second
	if t := r.URL.Query().Get("timeout"); t != "" {
		parsed, err := time.ParseDuration(t)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Error: "invalid timeout: " + t})
			return
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

	recordType := strings.ToLower(r.URL.Query().Get("type"))

	if lookup.IsIP(target) && recordType == "" {
		recordType = "ptr"
	}

	var result lookup.Result
	var err error

	switch recordType {
	case "ptr":
		result, err = lookup.Reverse(target)
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
		result, err = lookup.Forward(target)
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
	mux.HandleFunc("/scan", handleScan)
	mux.HandleFunc("/check", handleCheck)
	mux.HandleFunc("/lookup", handleLookup)

	// Verify the address is valid before starting
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}

	log.Printf("netu service starting on %s:%s", host, port)
	log.Printf("endpoints: /health, /scan, /check, /lookup")
	return http.ListenAndServe(addr, mux)
}
