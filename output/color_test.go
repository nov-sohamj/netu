package output

import (
	"strings"
	"testing"
)

func TestNoColorStripsANSI(t *testing.T) {
	NoColor = true
	defer func() { NoColor = false }()

	if got := Green("hello"); got != "hello" {
		t.Fatalf("expected 'hello', got %q", got)
	}
	if got := Red("err"); got != "err" {
		t.Fatalf("expected 'err', got %q", got)
	}
	if got := Bold("text"); got != "text" {
		t.Fatalf("expected 'text', got %q", got)
	}
}

func TestColorAddsANSI(t *testing.T) {
	NoColor = false

	got := Green("ok")
	if !strings.Contains(got, "\033[") {
		t.Fatalf("expected ANSI escape in %q", got)
	}
	if !strings.Contains(got, "ok") {
		t.Fatalf("expected 'ok' in %q", got)
	}
}

func TestStatus(t *testing.T) {
	NoColor = true
	defer func() { NoColor = false }()

	tests := []struct {
		input string
		want  string
	}{
		{"pass", "pass"},
		{"fail", "fail"},
		{"warn", "warn"},
		{"other", "other"},
	}

	for _, tt := range tests {
		got := Status(tt.input)
		if got != tt.want {
			t.Errorf("Status(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIcon(t *testing.T) {
	NoColor = true
	defer func() { NoColor = false }()

	if got := Icon("pass"); got != "+" {
		t.Fatalf("Icon(pass) = %q, want +", got)
	}
	if got := Icon("fail"); got != "x" {
		t.Fatalf("Icon(fail) = %q, want x", got)
	}
	if got := Icon("warn"); got != "!" {
		t.Fatalf("Icon(warn) = %q, want !", got)
	}
}

func TestPortState(t *testing.T) {
	NoColor = true
	defer func() { NoColor = false }()

	if got := PortState(true); got != "open" {
		t.Fatalf("PortState(true) = %q, want 'open'", got)
	}
	if got := PortState(false); got != "closed" {
		t.Fatalf("PortState(false) = %q, want 'closed'", got)
	}
}
