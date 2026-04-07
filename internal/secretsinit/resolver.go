// Package secretsinit provides secret resolution logic used by the secrets-init
// binary to resolve awssm: placeholders at container startup.
package secretsinit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"crypto/rand"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	awssmPrefix       = "awssm:"
	awssmPrefixLegacy = "awssm://"
	envErrFormat      = "env %q: %w"
	maxRetries        = 3
	baseBackoff       = 200 * time.Millisecond
	maxBackoff        = 5 * time.Second
)

// inlinePattern matches ${awssm:secret#key} or ${awssm:secret#key#version} within strings.
var inlinePattern = regexp.MustCompile(`\$\{awssm:([^}]+)\}`)

// SMClient is a minimal interface for AWS Secrets Manager operations.
type SMClient interface {
	GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// NewSMClient constructs an AWS Secrets Manager client from the ambient config.
func NewSMClient(ctx context.Context, region string) (SMClient, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("secretsinit: failed to load AWS config: %w", err)
	}
	return secretsmanager.NewFromConfig(cfg), nil
}

// IsPlaceholder reports whether value contains an awssm: secret reference.
// Matches both full-value placeholders and inline ${awssm:...} interpolation.
func IsPlaceholder(value string) bool {
	return strings.HasPrefix(value, awssmPrefix) || inlinePattern.MatchString(value)
}

// trimPrefix strips the awssm: or awssm:// prefix from a placeholder.
func trimPrefix(placeholder string) string {
	if strings.HasPrefix(placeholder, awssmPrefixLegacy) {
		return strings.TrimPrefix(placeholder, awssmPrefixLegacy)
	}
	return strings.TrimPrefix(placeholder, awssmPrefix)
}

// Placeholder holds parsed components of an awssm: reference.
type Placeholder struct {
	SecretName string
	Key        string
	HasKey     bool
	Version    string // VersionStage or VersionId (e.g., "AWSPREVIOUS", "v-abc123")
	HasVersion bool
}

// ParsePlaceholder extracts components from a placeholder.
//
// Formats:
//
//	awssm:<secret>                    → secret only
//	awssm:<secret>#<key>              → secret + JSON key
//	awssm:<secret>#<key>#<version>    → secret + JSON key + version
//	awssm://<secret>#<key>            → legacy prefix
func ParsePlaceholder(placeholder string) (secretName, key string, hasKey bool, err error) {
	p, err := parseFull(placeholder)
	if err != nil {
		return "", "", false, err
	}
	return p.SecretName, p.Key, p.HasKey, nil
}

// parseFull parses a full placeholder including version.
func parseFull(placeholder string) (*Placeholder, error) {
	trimmed := trimPrefix(placeholder)
	if trimmed == "" {
		return nil, fmt.Errorf("secretsinit: empty secret reference in %q", placeholder)
	}

	parts := strings.SplitN(trimmed, "#", 3)
	p := &Placeholder{SecretName: parts[0]}

	if p.SecretName == "" {
		return nil, fmt.Errorf("secretsinit: missing secret name in %q", placeholder)
	}

	if len(parts) >= 2 && parts[1] != "" {
		p.Key = parts[1]
		p.HasKey = true
	}

	if len(parts) >= 3 && parts[2] != "" {
		p.Version = parts[2]
		p.HasVersion = true
	}

	return p, nil
}

// parseInlineRef parses the inner part of ${awssm:...} (no prefix).
func parseInlineRef(ref string) (*Placeholder, error) {
	if ref == "" {
		return nil, fmt.Errorf("secretsinit: empty inline reference")
	}

	parts := strings.SplitN(ref, "#", 3)
	p := &Placeholder{SecretName: parts[0]}

	if p.SecretName == "" {
		return nil, fmt.Errorf("secretsinit: missing secret name in inline reference %q", ref)
	}

	if len(parts) >= 2 && parts[1] != "" {
		p.Key = parts[1]
		p.HasKey = true
	}

	if len(parts) >= 3 && parts[2] != "" {
		p.Version = parts[2]
		p.HasVersion = true
	}

	return p, nil
}

// ResolveOptions configures resolution behavior.
type ResolveOptions struct {
	IgnoreMissing bool // if true, failed resolutions return empty string instead of error
}

// ResolveAll resolves all awssm: placeholders in the given env map.
// Supports full-value placeholders (awssm:...) and inline interpolation (${awssm:...}).
// Deduplicates secret fetches — same secret name + version is fetched once.
func ResolveAll(ctx context.Context, client SMClient, envs map[string]string, opts ...ResolveOptions) (map[string]string, error) {
	var opt ResolveOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	// Cache key is "secretName" or "secretName@version".
	secretCache := make(map[string]string)

	resolved := make(map[string]string, len(envs))
	for k, v := range envs {
		if !IsPlaceholder(v) {
			resolved[k] = v
			continue
		}

		val, err := resolveValue(ctx, client, v, secretCache)
		if err != nil {
			if opt.IgnoreMissing {
				resolved[k] = ""
				continue
			}
			return nil, fmt.Errorf(envErrFormat, k, err)
		}
		resolved[k] = val
	}

	return resolved, nil
}

// resolveValue resolves a single env var value. Handles both full-value and inline patterns.
func resolveValue(ctx context.Context, client SMClient, value string, cache map[string]string) (string, error) {
	// Check for inline interpolation: ${awssm:...}
	if inlinePattern.MatchString(value) && !strings.HasPrefix(value, awssmPrefix) {
		return resolveInline(ctx, client, value, cache)
	}

	// Full-value placeholder: awssm:...
	if strings.HasPrefix(value, awssmPrefix) {
		// Could also contain inline patterns mixed with a prefix — handle as inline if it has ${
		if strings.Contains(value, "${awssm:") {
			return resolveInline(ctx, client, value, cache)
		}
		return resolveFullValue(ctx, client, value, cache)
	}

	return value, nil
}

// resolveFullValue resolves a full-value awssm: placeholder.
func resolveFullValue(ctx context.Context, client SMClient, placeholder string, cache map[string]string) (string, error) {
	p, err := parseFull(placeholder)
	if err != nil {
		return "", err
	}

	raw, err := fetchCached(ctx, client, p.SecretName, p.Version, cache)
	if err != nil {
		return "", err
	}

	if !p.HasKey {
		return raw, nil
	}

	return ExtractJSONKey(raw, p.SecretName, p.Key)
}

// resolveInline resolves all ${awssm:...} patterns within a string.
func resolveInline(ctx context.Context, client SMClient, value string, cache map[string]string) (string, error) {
	var resolveErr error

	result := inlinePattern.ReplaceAllStringFunc(value, func(match string) string {
		if resolveErr != nil {
			return match
		}

		// Extract the inner reference (between ${ and }).
		inner := match[len("${awssm:"):]
		inner = inner[:len(inner)-1] // strip trailing }

		p, err := parseInlineRef(inner)
		if err != nil {
			resolveErr = err
			return match
		}

		raw, err := fetchCached(ctx, client, p.SecretName, p.Version, cache)
		if err != nil {
			resolveErr = err
			return match
		}

		if !p.HasKey {
			return raw
		}

		val, err := ExtractJSONKey(raw, p.SecretName, p.Key)
		if err != nil {
			resolveErr = err
			return match
		}

		return val
	})

	if resolveErr != nil {
		return "", resolveErr
	}
	return result, nil
}

// fetchCached retrieves a secret value, using a cache keyed by name+version.
func fetchCached(ctx context.Context, client SMClient, secretName, version string, cache map[string]string) (string, error) {
	cacheKey := secretName
	if version != "" {
		cacheKey = secretName + "@" + version
	}

	if cached, ok := cache[cacheKey]; ok {
		return cached, nil
	}

	raw, err := fetchSecret(ctx, client, secretName, version)
	if err != nil {
		return "", err
	}

	cache[cacheKey] = raw
	return raw, nil
}

// fetchSecret retrieves the raw secret string from AWS Secrets Manager.
// Retries with exponential backoff + jitter on transient errors (429, 5xx, network).
func fetchSecret(ctx context.Context, client SMClient, secretName, version string) (string, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}

	if version != "" {
		if isVersionStage(version) {
			input.VersionStage = aws.String(version)
		} else {
			input.VersionId = aws.String(version)
		}
	}

	var lastErr error
	for attempt := range maxRetries {
		out, err := client.GetSecretValue(ctx, input)
		if err == nil {
			if out.SecretString == nil {
				return "", fmt.Errorf("secretsinit: secret %q has no string value (binary secrets not supported)", secretName)
			}
			return *out.SecretString, nil
		}

		if !isRetryable(err) {
			return "", fmt.Errorf("secretsinit: failed to fetch secret %q: %w", secretName, err)
		}

		lastErr = err
		if attempt < maxRetries-1 {
			sleep := backoffWithJitter(attempt)
			select {
			case <-ctx.Done():
				return "", fmt.Errorf("secretsinit: failed to fetch secret %q: %w", secretName, ctx.Err())
			case <-time.After(sleep):
			}
		}
	}

	return "", fmt.Errorf("secretsinit: failed to fetch secret %q after %d retries: %w", secretName, maxRetries, lastErr)
}

// isRetryable returns true for transient errors that should be retried.
func isRetryable(err error) bool {
	var httpErr *smithyhttp.ResponseError
	if errors.As(err, &httpErr) {
		code := httpErr.HTTPStatusCode()
		return code == http.StatusTooManyRequests || code >= http.StatusInternalServerError
	}
	// Network errors, timeouts, etc. are retryable.
	return strings.Contains(err.Error(), "connection") ||
		strings.Contains(err.Error(), "timeout") ||
		strings.Contains(err.Error(), "reset")
}

// backoffWithJitter returns a backoff duration with cryptographically random jitter.
func backoffWithJitter(attempt int) time.Duration {
	backoff := baseBackoff * (1 << attempt) // exponential: 200ms, 400ms, 800ms...
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	// Add jitter: 50-150% of backoff using crypto/rand.
	n, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return backoff
	}
	jitterPct := 0.5 + float64(n.Int64())/100.0
	return time.Duration(float64(backoff) * jitterPct)
}

// isVersionStage returns true if the version string is a known AWS version stage.
func isVersionStage(version string) bool {
	stages := map[string]bool{
		"AWSCURRENT":  true,
		"AWSPREVIOUS": true,
		"AWSPENDING":  true,
	}
	return stages[version]
}

// ExtractJSONKey parses raw as a JSON object and returns the string value at key.
// Handles string, number, boolean, and null JSON values.
func ExtractJSONKey(raw, secretName, key string) (string, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return "", fmt.Errorf("secretsinit: secret %q is not a JSON object, cannot extract key %q", secretName, key)
	}
	val, ok := m[key]
	if !ok {
		return "", fmt.Errorf("secretsinit: key %q not found in secret %q", key, secretName)
	}
	if val == nil {
		return "", fmt.Errorf("secretsinit: key %q in secret %q is null", key, secretName)
	}
	return fmt.Sprintf("%v", val), nil
}
