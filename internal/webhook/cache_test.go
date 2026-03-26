package webhook

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const (
	testCacheKey    = "secret-a"
	testCacheValue  = "value-a"
	testFetchedVal  = "fetched-value"
)

func TestSecretCacheGetSet(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache(5*time.Second, zap.NewNop())
	cache.Set(testCacheKey, testCacheValue)

	val, ok := cache.Get(testCacheKey)
	assert.True(t, ok)
	assert.Equal(t, testCacheValue, val)
}

func TestSecretCacheMiss(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache(5*time.Second, zap.NewNop())

	val, ok := cache.Get("nonexistent")
	assert.False(t, ok)
	assert.Empty(t, val)
}

func TestSecretCacheExpiry(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache(50*time.Millisecond, zap.NewNop())
	cache.Set(testCacheKey, testCacheValue)

	time.Sleep(100 * time.Millisecond)

	val, ok := cache.Get(testCacheKey)
	assert.False(t, ok, "expired entry should return miss")
	assert.Empty(t, val)
}

func TestSecretCacheDisabledWhenTTLZero(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache(0, zap.NewNop())
	cache.Set(testCacheKey, testCacheValue)

	val, ok := cache.Get(testCacheKey)
	assert.False(t, ok, "TTL 0 should disable cache")
	assert.Empty(t, val)
}

func TestSecretCacheLen(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache(5*time.Second, zap.NewNop())
	assert.Equal(t, 0, cache.Len())

	cache.Set("a", "1")
	cache.Set("b", "2")
	assert.Equal(t, 2, cache.Len())
}

func TestSecretCacheGetOrFetchHit(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache(5*time.Second, zap.NewNop())
	cache.Set(testCacheKey, "cached-value")

	callCount := 0
	val, err := cache.GetOrFetch(testCacheKey, func() (string, error) {
		callCount++
		return testFetchedVal, nil
	})

	require.NoError(t, err)
	assert.Equal(t, "cached-value", val, "should return cached value")
	assert.Equal(t, 0, callCount, "fetch should not be called on cache hit")
}

func TestSecretCacheGetOrFetchMiss(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache(5*time.Second, zap.NewNop())

	val, err := cache.GetOrFetch(testCacheKey, func() (string, error) {
		return testFetchedVal, nil
	})

	require.NoError(t, err)
	assert.Equal(t, testFetchedVal, val)

	// Verify it was cached.
	cached, ok := cache.Get(testCacheKey)
	assert.True(t, ok)
	assert.Equal(t, testFetchedVal, cached)
}

func TestSecretCacheEvictExpired(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache(50*time.Millisecond, zap.NewNop())
	cache.Set("a", "1")
	cache.Set("b", "2")
	assert.Equal(t, 2, cache.Len())

	time.Sleep(100 * time.Millisecond)
	cache.evictExpired()
	assert.Equal(t, 0, cache.Len(), "expired entries should be evicted")
}

func TestSecretCacheStartCleanup(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache(50*time.Millisecond, zap.NewNop())
	cache.Set("a", "1")

	ctx, cancel := context.WithCancel(context.Background())
	cache.StartCleanup(ctx, 60*time.Millisecond)

	// Wait for entry to expire and cleanup to run.
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, 0, cache.Len(), "cleanup should evict expired entries")

	cancel()
}

func TestSecretCacheStartCleanupDisabledWhenTTLZero(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache(0, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Should not panic or start goroutine.
	cache.StartCleanup(ctx, 60*time.Millisecond)
}
