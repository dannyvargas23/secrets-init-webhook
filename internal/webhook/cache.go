package webhook

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

// cacheEntry holds a cached secret value and its expiration time.
type cacheEntry struct {
	value     string
	expiresAt time.Time
}

// SecretCache is a thread-safe in-memory TTL cache for secret values.
// It is shared across all admission requests to reduce API calls during
// high-frequency pod scaling. Includes singleflight to coalesce concurrent
// fetches for the same secret into a single API call.
type SecretCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
	log     *zap.Logger
	flight  singleflight.Group
}

// NewSecretCache creates a shared cache with the given TTL.
// If ttl is 0, the cache is disabled (Get always returns miss, Do bypassed).
func NewSecretCache(ttl time.Duration, log *zap.Logger) *SecretCache {
	return &SecretCache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
		log:     log,
	}
}

// Get returns the cached value for the given secret name.
// Returns ("", false) on cache miss or expired entry.
func (c *SecretCache) Get(secretName string) (string, bool) {
	if c.ttl == 0 {
		return "", false
	}

	c.mu.RLock()
	entry, ok := c.entries[secretName]
	c.mu.RUnlock()

	if !ok {
		return "", false
	}

	if time.Now().After(entry.expiresAt) {
		return "", false
	}

	return entry.value, true
}

// Set stores a secret value in the cache with the configured TTL.
func (c *SecretCache) Set(secretName, value string) {
	if c.ttl == 0 {
		return
	}

	c.mu.Lock()
	c.entries[secretName] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// GetOrFetch returns the cached value or calls fetchFn exactly once across all
// concurrent callers for the same key (singleflight). The result is cached for
// the configured TTL.
func (c *SecretCache) GetOrFetch(secretName string, fetchFn func() (string, error)) (string, error) {
	// Fast path: cache hit.
	if val, ok := c.Get(secretName); ok {
		return val, nil
	}

	// Singleflight: coalesce concurrent fetches for the same secret.
	result, err, _ := c.flight.Do(secretName, func() (any, error) {
		// Double-check cache inside the flight — another goroutine may have
		// populated it between the Get above and winning the flight.
		if val, ok := c.Get(secretName); ok {
			return val, nil
		}

		val, err := fetchFn()
		if err != nil {
			return nil, err
		}

		c.Set(secretName, val)
		return val, nil
	})
	if err != nil {
		return "", err
	}
	return result.(string), nil
}

// StartCleanup runs a background goroutine that evicts expired entries
// at the given interval. It stops when the context is cancelled.
func (c *SecretCache) StartCleanup(ctx context.Context, interval time.Duration) {
	if c.ttl == 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.evictExpired()
			}
		}
	}()
}

// evictExpired removes all entries whose TTL has passed.
func (c *SecretCache) evictExpired() {
	now := time.Now()
	c.mu.Lock()
	evicted := 0
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
			evicted++
		}
	}
	c.mu.Unlock()

	if evicted > 0 {
		c.log.Debug("cache: evicted expired entries", zap.Int("count", evicted))
	}
}

// Len returns the number of entries currently in the cache.
func (c *SecretCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
