package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dannyvargas23/secrets-init-webhook/internal/config"
)

const (
	testRegion        = "us-east-1"
	testInitContainer = "init-container"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
		check   func(t *testing.T, cfg *config.Config)
	}{
		{
			name:    "missing AWS_REGION returns error",
			env:     map[string]string{},
			wantErr: "AWS_REGION is required",
		},
		{
			name:    "invalid LOG_LEVEL returns error",
			env:     map[string]string{"AWS_REGION": testRegion, "LOG_LEVEL": "verbose"},
			wantErr: "LOG_LEVEL",
		},
		{
			name: "minimal valid config uses defaults",
			env:  map[string]string{"AWS_REGION": testRegion},
			check: func(t *testing.T, cfg *config.Config) {
				t.Helper()
				assert.Equal(t, 8443, cfg.Port)
				assert.Equal(t, "/tls/tls.crt", cfg.TLSCertPath)
				assert.Equal(t, "/tls/tls.key", cfg.TLSKeyPath)
				assert.Equal(t, "info", cfg.LogLevel)
				assert.Equal(t, 9090, cfg.MetricsPort)
				assert.Empty(t, cfg.OTLPEndpoint)
			},
		},
		{
			name: "all env vars set correctly",
			env: map[string]string{
				"AWS_REGION":    "eu-west-1",
				"PORT":          "9443",
				"LOG_LEVEL":     "debug",
				"OTLP_ENDPOINT": "otel-collector:4317",
				"METRICS_PORT":  "9091",
			},
			check: func(t *testing.T, cfg *config.Config) {
				t.Helper()
				assert.Equal(t, "eu-west-1", cfg.AWSRegion)
				assert.Equal(t, 9443, cfg.Port)
				assert.Equal(t, "debug", cfg.LogLevel)
				assert.Equal(t, "otel-collector:4317", cfg.OTLPEndpoint)
				assert.Equal(t, 9091, cfg.MetricsPort)
			},
		},
		{
			name:    "invalid MUTATION_MODE returns error",
			env:     map[string]string{"AWS_REGION": testRegion, "MUTATION_MODE": "invalid"},
			wantErr: "MUTATION_MODE",
		},
		{
			name:    "init-container mode without image returns error",
			env:     map[string]string{"AWS_REGION": testRegion, "MUTATION_MODE": testInitContainer},
			wantErr: "SECRETS_INIT_IMAGE is required",
		},
		{
			name: "init-container mode with image succeeds",
			env: map[string]string{
				"AWS_REGION":         testRegion,
				"MUTATION_MODE":      testInitContainer,
				"SECRETS_INIT_IMAGE": "123456.dkr.ecr.us-east-1.amazonaws.com/secrets-init-secrets-init@sha256:abc123",
			},
			check: func(t *testing.T, cfg *config.Config) {
				t.Helper()
				assert.Equal(t, testInitContainer, cfg.MutationMode)
				assert.Equal(t, "123456.dkr.ecr.us-east-1.amazonaws.com/secrets-init-secrets-init@sha256:abc123", cfg.SecretsInitImage)
			},
		},
		{
			name: "direct mode defaults",
			env:  map[string]string{"AWS_REGION": testRegion},
			check: func(t *testing.T, cfg *config.Config) {
				t.Helper()
				assert.Equal(t, "direct", cfg.MutationMode)
				assert.Empty(t, cfg.SecretsInitImage)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set env vars for this test case.
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			cfg, err := config.Load()

			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cfg)
			tc.check(t, cfg)
		})
	}
}
