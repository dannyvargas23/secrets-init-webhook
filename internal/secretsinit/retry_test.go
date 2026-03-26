package secretsinit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackoffWithJitter(t *testing.T) {
	t.Parallel()

	for attempt := range 5 {
		d := backoffWithJitter(attempt)
		assert.Greater(t, d, time.Duration(0), "backoff should be positive")
		assert.LessOrEqual(t, d, maxBackoff*2, "backoff should not exceed 2x max")
	}
}

func TestBackoffIsExponential(t *testing.T) {
	t.Parallel()

	// Run many samples to check that later attempts generally have longer backoffs.
	var sum0, sum2 time.Duration
	for range 100 {
		sum0 += backoffWithJitter(0)
		sum2 += backoffWithJitter(2)
	}
	avg0 := sum0 / 100
	avg2 := sum2 / 100
	assert.Greater(t, avg2, avg0, "attempt 2 should have higher average backoff than attempt 0")
}

func TestCopyTo(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dst := filepath.Join(dir, "secrets-init")

	err := CopyTo(dst)
	require.NoError(t, err)

	info, err := os.Stat(dst)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0), "copied binary should not be empty")

	// Check CA certs were copied if available.
	certPath := dst + ".ca-certificates.crt"
	if findCACerts() != "" {
		_, err = os.Stat(certPath)
		assert.NoError(t, err, "CA certs should be copied alongside binary")
	}
}
