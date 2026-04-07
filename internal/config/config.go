// Package config loads and validates runtime configuration using viper.
//
// Why viper: the prompt requires viper explicitly. Beyond that, viper provides
// automatic env var binding, type coercion, default values, and future support
// for config files and remote config sources — all without manual os.Getenv
// boilerplate. It follows 12-Factor App principles out of the box.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all runtime configuration for the webhook server.
// Fields are populated from environment variables via viper's AutomaticEnv.
// All env var names map 1:1 to struct field names (uppercased, underscored).
type Config struct {
	// Port is the HTTPS port the webhook server listens on. Default: 8443.
	Port int

	// TLSCertPath is the path to the TLS certificate file mounted from cert-manager.
	TLSCertPath string

	// TLSKeyPath is the path to the TLS private key file mounted from cert-manager.
	TLSKeyPath string

	// AWSRegion is the AWS region for the Secrets Manager client. Required.
	AWSRegion string

	// LogLevel controls log verbosity: debug, info, warn, error. Default: info.
	LogLevel string

	// OTLPEndpoint is the OpenTelemetry collector gRPC endpoint for trace export.
	// If empty, tracing is disabled. Example: "otel-collector.monitoring:4317"
	OTLPEndpoint string

	// MetricsPort is the port for the Prometheus /metrics HTTP endpoint. Default: 9090.
	MetricsPort int

	// SecretsInitImage is the full image reference for the secrets-init init container.
	// Required. Example: "123456.dkr.ecr.us-east-1.amazonaws.com/secrets-init-vol@sha256:abc123"
	SecretsInitImage string
}

// Load reads and validates configuration from environment variables.
// Returns a descriptive error if any required variable is missing or invalid.
func Load() (*Config, error) {
	v := viper.New()

	// AutomaticEnv maps env vars to config keys automatically.
	// SetEnvKeyReplacer allows keys with underscores to map to env vars with underscores.
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Defaults — all non-required fields have sensible production defaults.
	v.SetDefault("port", 8443)
	v.SetDefault("tls_cert_path", "/tls/tls.crt")
	v.SetDefault("tls_key_path", "/tls/tls.key")
	v.SetDefault("log_level", "info")
	v.SetDefault("otlp_endpoint", "")
	v.SetDefault("metrics_port", 9090)
	v.SetDefault("secrets_init_image", "")

	// Validate required fields before constructing the Config.
	if v.GetString("aws_region") == "" {
		return nil, fmt.Errorf("config: AWS_REGION is required but not set")
	}

	logLevel := v.GetString("log_level")
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[logLevel] {
		return nil, fmt.Errorf("config: LOG_LEVEL %q is invalid, must be one of: debug, info, warn, error", logLevel)
	}

	secretsInitImage := v.GetString("secrets_init_image")
	if secretsInitImage == "" {
		return nil, fmt.Errorf("config: SECRETS_INIT_IMAGE is required but not set")
	}

	return &Config{
		Port:             v.GetInt("port"),
		TLSCertPath:      v.GetString("tls_cert_path"),
		TLSKeyPath:       v.GetString("tls_key_path"),
		AWSRegion:        v.GetString("aws_region"),
		LogLevel:         logLevel,
		OTLPEndpoint:     v.GetString("otlp_endpoint"),
		MetricsPort:      v.GetInt("metrics_port"),
		SecretsInitImage: secretsInitImage,
	}, nil
}
