package main

import (
	"sync"
	"time"
)

// CachedResponse represents a cached HTTP response with its status, data, and the time it was stored.
type CachedResponse struct {
	Status   string
	Data     string
	StoredAt time.Time
}

// ResponseCache provides methods for storing and retrieving cached HTTP responses using a name and key.
type ResponseCache interface {
	// Get retrieves a CachedResponse from the cache using the specified name and key. Returns the response and a boolean indicating if found.
	Get(name, key string) (CachedResponse, bool)

	// Set stores a CachedResponse in the cache with the specified name and key.
	Set(name, key string, resp CachedResponse)
}

// InMemoryResponseCache manages a thread-safe in-memory cache for HTTP responses with a defined time-to-live (TTL).
type InMemoryResponseCache struct {
	entries map[string]CachedResponse
	mu      sync.RWMutex
	ttl     time.Duration
}

// NewInMemoryResponseCache creates a new in-memory response cache with a specified time-to-live duration for entries.
func NewInMemoryResponseCache(ttl time.Duration) *InMemoryResponseCache {
	return &InMemoryResponseCache{
		entries: make(map[string]CachedResponse),
		ttl:     ttl,
	}
}

// makeKey generates a unique cache key by combining the provided name and key with a "|" separator.
func (c *InMemoryResponseCache) makeKey(name, key string) string {
	return name + "|" + key
}

// Get retrieves a cached response by name and key, returning its value and a boolean indicating presence in the cache.
func (c *InMemoryResponseCache) Get(name, key string) (CachedResponse, bool) {
	if c == nil || c.ttl <= 0 {
		return CachedResponse{}, false
	}

	cacheKey := c.makeKey(name, key)

	c.mu.RLock()
	entry, ok := c.entries[cacheKey]
	c.mu.RUnlock()

	if !ok {
		return CachedResponse{}, false
	}

	if time.Since(entry.StoredAt) > c.ttl {
		// expired; remove lazily
		c.mu.Lock()
		delete(c.entries, cacheKey)
		c.mu.Unlock()

		return CachedResponse{}, false
	}

	return entry, true
}

// Set stores a CachedResponse in the cache using a combination of name and key as the cache key. Overwrites existing entries.
func (c *InMemoryResponseCache) Set(name, key string, resp CachedResponse) {
	if c == nil || c.ttl <= 0 {
		return
	}

	resp.StoredAt = time.Now()
	cacheKey := c.makeKey(name, key)

	c.mu.Lock()
	c.entries[cacheKey] = resp
	c.mu.Unlock()
}

var _ ResponseCache = &InMemoryResponseCache{}
