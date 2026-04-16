package lookup

import (
	"testing"
	"time"
)

func TestCacheSetAndGet(t *testing.T) {
	c := NewCache(1 * time.Minute)
	r := Result{Type: "A", Records: []string{"1.2.3.4"}}
	c.Set("test", r)

	got, ok := c.Get("test")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Type != "A" || len(got.Records) != 1 || got.Records[0] != "1.2.3.4" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestCacheMiss(t *testing.T) {
	c := NewCache(1 * time.Minute)
	_, ok := c.Get("missing")
	if ok {
		t.Fatal("expected cache miss")
	}
}

func TestCacheExpiry(t *testing.T) {
	c := NewCache(10 * time.Millisecond)
	c.Set("key", Result{Type: "A", Records: []string{"1.1.1.1"}})

	// Should hit immediately
	_, ok := c.Get("key")
	if !ok {
		t.Fatal("expected cache hit before expiry")
	}

	time.Sleep(20 * time.Millisecond)

	// Should miss after expiry
	_, ok = c.Get("key")
	if ok {
		t.Fatal("expected cache miss after expiry")
	}
}

func TestCacheSize(t *testing.T) {
	c := NewCache(1 * time.Minute)
	if c.Size() != 0 {
		t.Fatalf("expected size 0, got %d", c.Size())
	}

	c.Set("a", Result{Type: "A", Records: []string{"1.1.1.1"}})
	c.Set("b", Result{Type: "A", Records: []string{"2.2.2.2"}})
	if c.Size() != 2 {
		t.Fatalf("expected size 2, got %d", c.Size())
	}
}

func TestCacheOverwrite(t *testing.T) {
	c := NewCache(1 * time.Minute)
	c.Set("key", Result{Type: "A", Records: []string{"old"}})
	c.Set("key", Result{Type: "A", Records: []string{"new"}})

	got, ok := c.Get("key")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Records[0] != "new" {
		t.Fatalf("expected 'new', got %q", got.Records[0])
	}
}
