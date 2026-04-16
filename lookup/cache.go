package lookup

import (
	"sync"
	"time"
)

type cacheEntry struct {
	result  Result
	expires time.Time
}

type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

var defaultCache = NewCache(5 * time.Minute)

func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
	}
}

func (c *Cache) Get(key string) (Result, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expires) {
		return Result{}, false
	}
	return entry.result, true
}

func (c *Cache) Set(key string, result Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{
		result:  result,
		expires: time.Now().Add(c.ttl),
	}
}

func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	count := 0
	now := time.Now()
	for _, e := range c.entries {
		if now.Before(e.expires) {
			count++
		}
	}
	return count
}

// CachedForward wraps Forward with caching.
func CachedForward(host string) (Result, error) {
	key := "fwd:" + host
	if r, ok := defaultCache.Get(key); ok {
		return r, nil
	}
	r, err := Forward(host)
	if err != nil {
		return r, err
	}
	defaultCache.Set(key, r)
	return r, nil
}

// CachedReverse wraps Reverse with caching.
func CachedReverse(ip string) (Result, error) {
	key := "rev:" + ip
	if r, ok := defaultCache.Get(key); ok {
		return r, nil
	}
	r, err := Reverse(ip)
	if err != nil {
		return r, err
	}
	defaultCache.Set(key, r)
	return r, nil
}
