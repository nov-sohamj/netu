package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func parseResponse(t *testing.T, w *httptest.ResponseRecorder) apiResponse {
	t.Helper()
	var resp apiResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %s (body: %s)", err, w.Body.String())
	}
	return resp
}

// --- Validation tests ---

func TestValidateHost(t *testing.T) {
	tests := []struct {
		host string
		ok   bool
	}{
		{"localhost", true},
		{"google.com", true},
		{"192.168.1.1", true},
		{"", false},
		{"host with spaces", false},
		{"host;rm -rf /", false},
		{"host|cmd", false},
		{"host&cmd", false},
	}
	for _, tt := range tests {
		if got := validateHost(tt.host); got != tt.ok {
			t.Errorf("validateHost(%q) = %v, want %v", tt.host, got, tt.ok)
		}
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		port int
		ok   bool
	}{
		{1, true},
		{80, true},
		{65535, true},
		{0, false},
		{-1, false},
		{65536, false},
	}
	for _, tt := range tests {
		if got := validatePort(tt.port); got != tt.ok {
			t.Errorf("validatePort(%d) = %v, want %v", tt.port, got, tt.ok)
		}
	}
}

// --- Handler tests ---

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	resp := parseResponse(t, w)
	if resp.Status != "ok" {
		t.Fatalf("expected status 'ok', got %q", resp.Status)
	}
}

func TestScanMissingParams(t *testing.T) {
	req := httptest.NewRequest("GET", "/scan", nil)
	w := httptest.NewRecorder()
	handleScan(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestScanInvalidHost(t *testing.T) {
	req := httptest.NewRequest("GET", "/scan?host=bad%20host&ports=80", nil)
	w := httptest.NewRecorder()
	handleScan(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	resp := parseResponse(t, w)
	if resp.Error != "invalid host" {
		t.Fatalf("expected 'invalid host', got %q", resp.Error)
	}
}

func TestScanPortRangeTooLarge(t *testing.T) {
	req := httptest.NewRequest("GET", "/scan?host=localhost&ports=1-20000", nil)
	w := httptest.NewRecorder()
	handleScan(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	resp := parseResponse(t, w)
	if resp.Error != "port range too large (max 10000)" {
		t.Fatalf("unexpected error: %q", resp.Error)
	}
}

func TestCheckMissingParams(t *testing.T) {
	req := httptest.NewRequest("GET", "/check", nil)
	w := httptest.NewRecorder()
	handleCheck(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCheckTooManyPorts(t *testing.T) {
	// Build 101 ports
	ports := "1"
	for i := 2; i <= 101; i++ {
		ports += ",1"
	}
	req := httptest.NewRequest("GET", "/check?host=localhost&ports="+ports, nil)
	w := httptest.NewRecorder()
	handleCheck(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	resp := parseResponse(t, w)
	if resp.Error != "too many ports (max 100)" {
		t.Fatalf("unexpected error: %q", resp.Error)
	}
}

func TestCheckInvalidPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/check?host=localhost&ports=abc", nil)
	w := httptest.NewRecorder()
	handleCheck(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestLookupMissingTarget(t *testing.T) {
	req := httptest.NewRequest("GET", "/lookup", nil)
	w := httptest.NewRecorder()
	handleLookup(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// --- Rate limiter tests ---

func TestRateLimiterAllows(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiterBlocks(t *testing.T) {
	rl := newRateLimiter(2, time.Minute)

	rl.allow("1.2.3.4")
	rl.allow("1.2.3.4")

	if rl.allow("1.2.3.4") {
		t.Fatal("third request should be blocked")
	}
}

func TestRateLimiterPerIP(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)

	rl.allow("1.1.1.1")
	if rl.allow("1.1.1.1") {
		t.Fatal("second request from same IP should be blocked")
	}

	// Different IP should be allowed
	if !rl.allow("2.2.2.2") {
		t.Fatal("request from different IP should be allowed")
	}
}

func TestRateLimiterResetsAfterWindow(t *testing.T) {
	rl := newRateLimiter(1, 20*time.Millisecond)

	rl.allow("1.1.1.1")
	if rl.allow("1.1.1.1") {
		t.Fatal("should be blocked before window expires")
	}

	time.Sleep(30 * time.Millisecond)

	if !rl.allow("1.1.1.1") {
		t.Fatal("should be allowed after window expires")
	}
}

// --- API key middleware test ---

func TestAPIKeyMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := apiKeyMiddleware("secret123", inner)

	// No key — should reject
	req := httptest.NewRequest("GET", "/scan", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401 without key, got %d", w.Code)
	}

	// Wrong key — should reject
	req = httptest.NewRequest("GET", "/scan", nil)
	req.Header.Set("X-API-Key", "wrong")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401 with wrong key, got %d", w.Code)
	}

	// Correct key via header — should allow
	req = httptest.NewRequest("GET", "/scan", nil)
	req.Header.Set("X-API-Key", "secret123")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 with correct key, got %d", w.Code)
	}

	// Correct key via query param — should allow
	req = httptest.NewRequest("GET", "/scan?key=secret123", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 with key in query, got %d", w.Code)
	}

	// Health endpoint — should always allow without key
	req = httptest.NewRequest("GET", "/health", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 for /health without key, got %d", w.Code)
	}
}
