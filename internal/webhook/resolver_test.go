package webhook_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dannyvargas23/secrets-init-webhook/internal/observability"
	"github.com/dannyvargas23/secrets-init-webhook/internal/webhook"
)

const testSecretName = "prod/myapp/config"

// mockSMClient implements SecretsManagerClient for testing.
// CallCount lets tests assert caching behaviour (only 1 API call per secret name).
type mockSMClient struct {
	secrets   map[string]string
	callCount map[string]int
	forcedErr error
}

func (m *mockSMClient) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
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

func newMock(secrets map[string]string) *mockSMClient {
	return &mockSMClient{secrets: secrets, callCount: make(map[string]int)}
}

func newTestMetrics() *observability.Metrics {
	// Use a fresh registry per test — avoids global state conflicts between parallel tests.
	return observability.NewMetrics(prometheus.NewRegistry())
}

func newTestResolver(client webhook.SecretsManagerClient) *webhook.Resolver {
	// TTL of 0 disables the shared cache in tests — isolates per-request behavior.
	cache := webhook.NewSecretCache(0, zap.NewNop())
	return webhook.NewResolver(client, cache, newTestMetrics(), zap.NewNop())
}

func TestResolver_Resolve(t *testing.T) {
	t.Parallel()

	jsonSecret := `{"DB_PASSWORD":"s3cr3t","DB_USER":"myapp","EMPTY":""}`
	plainSecret := "plain-token-value"

	tests := []struct {
		name        string
		secrets     map[string]string
		placeholder string
		want        string
		wantErrMsg  string
	}{
		{
			name:        "json secret with key extraction",
			secrets:     map[string]string{testSecretName: jsonSecret},
			placeholder: "awssm:prod/myapp/config#DB_PASSWORD",
			want:        "s3cr3t",
		},
		{
			name:        "json secret second key same secret",
			secrets:     map[string]string{testSecretName: jsonSecret},
			placeholder: "awssm:prod/myapp/config#DB_USER",
			want:        "myapp",
		},
		{
			name:        "json secret empty value is valid",
			secrets:     map[string]string{testSecretName: jsonSecret},
			placeholder: "awssm:prod/myapp/config#EMPTY",
			want:        "",
		},
		{
			name:        "plain string secret no key",
			secrets:     map[string]string{"prod/myapp/token": plainSecret},
			placeholder: "awssm:prod/myapp/token",
			want:        "plain-token-value",
		},
		{
			name:        "secret not found returns error",
			secrets:     map[string]string{},
			placeholder: "awssm:prod/myapp/missing",
			wantErrMsg:  "failed to fetch secret",
		},
		{
			name:        "json key not found returns error",
			secrets:     map[string]string{testSecretName: jsonSecret},
			placeholder: "awssm:prod/myapp/config#NONEXISTENT",
			wantErrMsg:  "key \"NONEXISTENT\" not found",
		},
		{
			name:        "non-json secret with key extraction returns error",
			secrets:     map[string]string{"prod/myapp/plain": "not-json"},
			placeholder: "awssm:prod/myapp/plain#somekey",
			wantErrMsg:  "not a JSON object",
		},
		{
			name:        "empty placeholder after prefix returns error",
			secrets:     map[string]string{},
			placeholder: "awssm:",
			wantErrMsg:  "empty secret reference",
		},
		{
			name:        "legacy prefix still works",
			secrets:     map[string]string{testSecretName: jsonSecret},
			placeholder: "awssm://prod/myapp/config#DB_PASSWORD",
			want:        "s3cr3t",
		},
		{
			name:        "non-awssm value is not a placeholder",
			secrets:     map[string]string{},
			placeholder: "info",
			wantErrMsg:  "failed to fetch secret", // IsPlaceholder check is caller's responsibility; Resolve tries to fetch "info"
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := newMock(tc.secrets)
			resolver := newTestResolver(mock)

			got, err := resolver.Resolve(context.Background(), tc.placeholder)

			if tc.wantErrMsg != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.wantErrMsg)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestResolver_CachePreventsDuplicateCalls asserts that resolving two keys from the
// same secret name results in exactly one GetSecretValue API call.
func TestResolver_CachePreventsDuplicateCalls(t *testing.T) {
	t.Parallel()

	mock := newMock(map[string]string{
		testSecretName: `{"A":"val-a","B":"val-b"}`,
	})
	resolver := newTestResolver(mock)
	ctx := context.Background()

	valA, err := resolver.Resolve(ctx, "awssm:prod/myapp/config#A")
	require.NoError(t, err)
	assert.Equal(t, "val-a", valA)

	valB, err := resolver.Resolve(ctx, "awssm:prod/myapp/config#B")
	require.NoError(t, err)
	assert.Equal(t, "val-b", valB)

	assert.Equal(t, 1, mock.callCount[testSecretName],
		"expected exactly 1 API call for the same secret name")
}

// TestResolver_APIErrorPropagated asserts that Secrets Manager API errors are
// wrapped and returned, not swallowed.
func TestResolver_APIErrorPropagated(t *testing.T) {
	t.Parallel()

	mock := newMock(map[string]string{})
	mock.forcedErr = fmt.Errorf("AccessDeniedException: access denied")
	resolver := newTestResolver(mock)

	_, err := resolver.Resolve(context.Background(), "awssm:prod/myapp/config#key")
	require.Error(t, err)
	assert.ErrorContains(t, err, "AccessDeniedException")
}
