package secretsinit_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dannyvargas23/secrets-init-webhook/internal/secretsinit"
)

type mockClient struct {
	secrets   map[string]string
	callCount map[string]int
	forcedErr error
}

func (m *mockClient) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if m.forcedErr != nil {
		return nil, m.forcedErr
	}
	name := aws.ToString(input.SecretId)
	m.callCount[name]++
	val, ok := m.secrets[name]
	if !ok {
		return nil, fmt.Errorf("ResourceNotFoundException: secret %q not found", name)
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(val)}, nil
}

func newMock(secrets map[string]string) *mockClient {
	return &mockClient{secrets: secrets, callCount: make(map[string]int)}
}

const (
	testSecretName   = "prod/myapp/config"
	testTokenSecret  = "prod/myapp/token"
	testKeyRef       = "awssm:prod/myapp/config#KEY"
	testMissingRef   = "awssm:prod/myapp/missing#KEY"
)

func TestIsPlaceholder(t *testing.T) {
	t.Parallel()
	assert.True(t, secretsinit.IsPlaceholder("awssm:prod/myapp/config"))
	assert.True(t, secretsinit.IsPlaceholder(testKeyRef))
	assert.True(t, secretsinit.IsPlaceholder("awssm://prod/myapp/config"), "legacy prefix should still match")
	assert.False(t, secretsinit.IsPlaceholder("plain-value"))
	assert.False(t, secretsinit.IsPlaceholder(""))
}

func TestParsePlaceholder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantName   string
		wantKey    string
		wantHasKey bool
		wantErr    string
	}{
		{
			name:       "plain secret",
			input:      "awssm:prod/myapp/token",
			wantName:   testTokenSecret,
			wantHasKey: false,
		},
		{
			name:       "secret with key",
			input:      "awssm:prod/myapp/config#DB_PASSWORD",
			wantName:   testSecretName,
			wantKey:    "DB_PASSWORD",
			wantHasKey: true,
		},
		{
			name:       "legacy prefix plain secret",
			input:      "awssm://prod/myapp/token",
			wantName:   testTokenSecret,
			wantHasKey: false,
		},
		{
			name:       "legacy prefix with key",
			input:      "awssm://prod/myapp/config#DB_PASSWORD",
			wantName:   testSecretName,
			wantKey:    "DB_PASSWORD",
			wantHasKey: true,
		},
		{
			name:    "empty after prefix",
			input:   "awssm:",
			wantErr: "empty secret reference",
		},
		{
			name:    "empty after legacy prefix",
			input:   "awssm://",
			wantErr: "empty secret reference",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			name, key, hasKey, err := secretsinit.ParsePlaceholder(tc.input)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantName, name)
			assert.Equal(t, tc.wantKey, key)
			assert.Equal(t, tc.wantHasKey, hasKey)
		})
	}
}

func TestResolveAll(t *testing.T) {
	t.Parallel()

	mock := newMock(map[string]string{
		testSecretName: `{"DB_PASSWORD":"s3cr3t","DB_USER":"myapp"}`,
		testTokenSecret:  "plain-token",
	})

	envs := map[string]string{
		"DB_PASSWORD": "awssm:prod/myapp/config#DB_PASSWORD",
		"DB_USER":     "awssm:prod/myapp/config#DB_USER",
		"TOKEN":       "awssm:prod/myapp/token",
		"LOG_LEVEL":   "info",
	}

	resolved, err := secretsinit.ResolveAll(context.Background(), mock, envs)
	require.NoError(t, err)

	assert.Equal(t, "s3cr3t", resolved["DB_PASSWORD"])
	assert.Equal(t, "myapp", resolved["DB_USER"])
	assert.Equal(t, "plain-token", resolved["TOKEN"])
	assert.Equal(t, "info", resolved["LOG_LEVEL"])

	// Same secret fetched only once despite two keys.
	assert.Equal(t, 1, mock.callCount[testSecretName])
}

func TestResolveAllSecretNotFound(t *testing.T) {
	t.Parallel()

	mock := newMock(map[string]string{})
	envs := map[string]string{
		"DB_PASSWORD": testMissingRef,
	}

	_, err := secretsinit.ResolveAll(context.Background(), mock, envs)
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to fetch secret")
}

func TestResolveAllIgnoreMissingReturnsEmpty(t *testing.T) {
	t.Parallel()

	mock := newMock(map[string]string{})
	envs := map[string]string{
		"DB_PASSWORD": testMissingRef,
		"LOG_LEVEL":   "info",
	}

	opts := secretsinit.ResolveOptions{IgnoreMissing: true}
	resolved, err := secretsinit.ResolveAll(context.Background(), mock, envs, opts)
	require.NoError(t, err)
	assert.Equal(t, "", resolved["DB_PASSWORD"])
	assert.Equal(t, "info", resolved["LOG_LEVEL"])
}

func TestResolveAllNoPlaceholders(t *testing.T) {
	t.Parallel()

	mock := newMock(map[string]string{})
	envs := map[string]string{
		"LOG_LEVEL": "info",
		"PORT":      "3000",
	}

	resolved, err := secretsinit.ResolveAll(context.Background(), mock, envs)
	require.NoError(t, err)
	assert.Equal(t, "info", resolved["LOG_LEVEL"])
	assert.Equal(t, "3000", resolved["PORT"])
	assert.Empty(t, mock.callCount)
}

func TestResolveAllVersionSupport(t *testing.T) {
	t.Parallel()

	mock := newMock(map[string]string{
		testSecretName: `{"DB_PASSWORD":"current-pass"}`,
	})

	envs := map[string]string{
		"DB_PASSWORD": "awssm:prod/myapp/config#DB_PASSWORD#AWSPREVIOUS",
	}

	// Mock doesn't differentiate versions, but this tests the parse + resolve flow.
	resolved, err := secretsinit.ResolveAll(context.Background(), mock, envs)
	require.NoError(t, err)
	assert.Equal(t, "current-pass", resolved["DB_PASSWORD"])
}

func TestResolveAllInlineInterpolation(t *testing.T) {
	t.Parallel()

	mock := newMock(map[string]string{
		testSecretName:     `{"DB_USER":"myapp","DB_PASSWORD":"s3cr3t"}`,
		"prod/myapp/host":  "db.example.com",
	})

	envs := map[string]string{
		"DATABASE_URL": "postgres://${awssm:prod/myapp/config#DB_USER}:${awssm:prod/myapp/config#DB_PASSWORD}@${awssm:prod/myapp/host}:5432/mydb",
		"LOG_LEVEL":    "info",
	}

	resolved, err := secretsinit.ResolveAll(context.Background(), mock, envs)
	require.NoError(t, err)
	assert.Equal(t, "postgres://myapp:s3cr3t@db.example.com:5432/mydb", resolved["DATABASE_URL"])
	assert.Equal(t, "info", resolved["LOG_LEVEL"])
}

func TestResolveAllInlineWithVersion(t *testing.T) {
	t.Parallel()

	mock := newMock(map[string]string{
		testSecretName: `{"DB_PASSWORD":"versioned-pass"}`,
	})

	envs := map[string]string{
		"CONN": "host:${awssm:prod/myapp/config#DB_PASSWORD#AWSPREVIOUS}@db",
	}

	resolved, err := secretsinit.ResolveAll(context.Background(), mock, envs)
	require.NoError(t, err)
	assert.Equal(t, "host:versioned-pass@db", resolved["CONN"])
}

func TestIsPlaceholderInline(t *testing.T) {
	t.Parallel()

	assert.True(t, secretsinit.IsPlaceholder("postgres://${awssm:prod/config#USER}@host"))
	assert.False(t, secretsinit.IsPlaceholder("postgres://user@host"))
}

func TestParsePlaceholderWithVersion(t *testing.T) {
	t.Parallel()

	name, key, hasKey, err := secretsinit.ParsePlaceholder("awssm:prod/myapp/config#DB_PASSWORD#AWSPREVIOUS")
	require.NoError(t, err)
	assert.Equal(t, testSecretName, name)
	assert.Equal(t, "DB_PASSWORD", key)
	assert.True(t, hasKey)
	// Version is parsed internally but ParsePlaceholder's public API doesn't expose it.
	// Full version support is tested via ResolveAll.
}

// transientMockClient returns errors for the first N calls, then succeeds.
type transientMockClient struct {
	secrets     map[string]string
	failCount   int
	callCount   int
	transientErr error
}

func (m *transientMockClient) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	m.callCount++
	if m.callCount <= m.failCount {
		return nil, m.transientErr
	}
	name := aws.ToString(input.SecretId)
	val, ok := m.secrets[name]
	if !ok {
		return nil, fmt.Errorf("ResourceNotFoundException: secret %q not found", name)
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(val)}, nil
}

func TestResolveAllRetryOnTransientError(t *testing.T) {
	t.Parallel()

	mock := &transientMockClient{
		secrets:      map[string]string{testSecretName: `{"KEY":"value"}`},
		failCount:    2,
		transientErr: fmt.Errorf("connection reset"),
	}

	envs := map[string]string{
		"KEY": testKeyRef,
	}

	resolved, err := secretsinit.ResolveAll(context.Background(), mock, envs)
	require.NoError(t, err)
	assert.Equal(t, "value", resolved["KEY"])
	assert.Equal(t, 3, mock.callCount, "expected 2 failures + 1 success = 3 calls")
}

func TestResolveAllExhaustsRetries(t *testing.T) {
	t.Parallel()

	mock := &transientMockClient{
		secrets:      map[string]string{testSecretName: `{"KEY":"value"}`},
		failCount:    10, // more than max retries
		transientErr: fmt.Errorf("connection timeout"),
	}

	envs := map[string]string{
		"KEY": testKeyRef,
	}

	_, err := secretsinit.ResolveAll(context.Background(), mock, envs)
	require.Error(t, err)
	assert.ErrorContains(t, err, "after 3 retries")
}

func TestResolveAllNoRetryOnNonTransient(t *testing.T) {
	t.Parallel()

	mock := newMock(map[string]string{})
	// 404 — not retryable
	envs := map[string]string{
		"KEY": testMissingRef,
	}

	_, err := secretsinit.ResolveAll(context.Background(), mock, envs)
	require.Error(t, err)
	assert.Equal(t, 1, mock.callCount["prod/myapp/missing"], "non-retryable error should not retry")
}

func TestResolveAllInlineError(t *testing.T) {
	t.Parallel()

	mock := newMock(map[string]string{})
	envs := map[string]string{
		"URL": "postgres://${awssm:prod/missing#USER}@host",
	}

	_, err := secretsinit.ResolveAll(context.Background(), mock, envs)
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to fetch secret")
}

func TestResolveAllMixedInlineAndPlain(t *testing.T) {
	t.Parallel()

	mock := newMock(map[string]string{
		testSecretName: `{"USER":"admin","PASS":"s3cr3t"}`,
	})

	envs := map[string]string{
		"DB_URL":    "postgres://${awssm:prod/myapp/config#USER}:${awssm:prod/myapp/config#PASS}@host/db",
		"LOG_LEVEL": "info",
		"DB_PASS":   "awssm:prod/myapp/config#PASS",
	}

	resolved, err := secretsinit.ResolveAll(context.Background(), mock, envs)
	require.NoError(t, err)
	assert.Equal(t, "postgres://admin:s3cr3t@host/db", resolved["DB_URL"])
	assert.Equal(t, "info", resolved["LOG_LEVEL"])
	assert.Equal(t, "s3cr3t", resolved["DB_PASS"])
}

func TestExtractJSONKeyNullValue(t *testing.T) {
	t.Parallel()

	_, err := secretsinit.ExtractJSONKey(`{"KEY": null}`, testSecretName, "KEY")
	require.Error(t, err)
	assert.ErrorContains(t, err, "is null")
}

func TestExtractJSONKeyNumericValue(t *testing.T) {
	t.Parallel()

	val, err := secretsinit.ExtractJSONKey(`{"PORT": 5432}`, testSecretName, "PORT")
	require.NoError(t, err)
	assert.Equal(t, "5432", val)
}

func TestExtractJSONKeyBooleanValue(t *testing.T) {
	t.Parallel()

	val, err := secretsinit.ExtractJSONKey(`{"ENABLED": true}`, testSecretName, "ENABLED")
	require.NoError(t, err)
	assert.Equal(t, "true", val)
}
