package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dannyvargas23/secrets-init-webhook/internal/config"
)

const (
	testRegion = "us-east-1"
	testImage  = "123456.dkr.ecr.us-east-1.amazonaws.com/secrets-init-vol@sha256:abc123"
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
			env:     map[string]string{"SECRETS_INIT_IMAGE": testImage},
			wantErr: "AWS_REGION is required",
		},
		{
			name:    "missing SECRETS_INIT_IMAGE returns error",
			env:     map[string]string{"AWS_REGION": testRegion},
			wantErr: "SECRETS_INIT_IMAGE is required",
		},
		{
			name:    "invalid LOG_LEVEL returns error",
			env:     map[string]string{"AWS_REGION": testRegion, "SECRETS_INIT_IMAGE": testImage, "LOG_LEVEL": "verbose"},
			wantErr: "LOG_LEVEL",
		},
		{
			name: "minimal valid config uses defaults",
			env:  map[string]string{"AWS_REGION": testRegion, "SECRETS_INIT_IMAGE": testImage},
			check: func(t *testing.T, cfg *config.Config) {
				t.Helper()
				assert.Equal(t, 8443, cfg.Port)
				assert.Equal(t, "/tls/tls.crt", cfg.TLSCertPath)
				assert.Equal(t, "/tls/tls.key", cfg.TLSKeyPath)
				assert.Equal(t, "info", cfg.LogLevel)
				assert.Equal(t, 9090, cfg.MetricsPort)
				assert.Empty(t, cfg.OTLPEndpoint)
				assert.Equal(t, testImage, cfg.SecretsInitImage)
			},
		},
		{
			name: "all env vars set correctly",
			env: map[string]string{
				"AWS_REGION":         "eu-west-1",
				"PORT":               "9443",
				"LOG_LEVEL":          "debug",
				"OTLP_ENDPOINT":      "otel-collector:4317",
				"METRICS_PORT":       "9091",
				"SECRETS_INIT_IMAGE": testImage,
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
