package webhook

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.uber.org/zap"

	"github.com/dannyvargas23/secrets-init-webhook/internal/observability"
	"github.com/dannyvargas23/secrets-init-webhook/internal/secretsinit"
)

const tracerName = "github.com/dannyvargas23/secrets-init-webhook"

// SecretsManagerClient is a purpose-specific interface defined at the consumer side.
//
// Why interface at consumer: the prompt requires interface segregation with small,
// purpose-specific interfaces at the consumer side. This decouples the resolver from
// the concrete AWS SDK type, enabling mock injection in tests without importing the
// full SDK in test binaries.
type SecretsManagerClient interface {
	GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// Resolver fetches and caches secret values from AWS Secrets Manager.
//
// Two cache layers:
//   - sharedCache: TTL-based, lives across requests, reduces API calls during scaling bursts
//   - requestCache: per-request, deduplicates within a single pod admission
type Resolver struct {
	client       SecretsManagerClient
	sharedCache  *SecretCache
	requestCache map[string]string
	metrics      *observability.Metrics
	log          *zap.Logger
}

// NewSMClient constructs a shared AWS Secrets Manager client from the ambient config.
//
// Why shared: aws-sdk-go-v2 config loading (credential discovery, endpoint resolution,
// region config) involves I/O and should happen once at startup, not per request.
// The resulting client is safe for concurrent use.
//
// context.Context is the first argument as required by the prompt for all I/O-bound functions.
func NewSMClient(ctx context.Context, region string) (SecretsManagerClient, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("resolver: failed to load AWS config: %w", err)
	}
	return secretsmanager.NewFromConfig(cfg), nil
}

// NewResolver constructs a per-request Resolver.
// The smClient and sharedCache are shared across requests; requestCache is fresh per instance.
func NewResolver(client SecretsManagerClient, sharedCache *SecretCache, metrics *observability.Metrics, log *zap.Logger) *Resolver {
	return &Resolver{
		client:       client,
		sharedCache:  sharedCache,
		requestCache: make(map[string]string),
		metrics:      metrics,
		log:          log,
	}
}

// IsPlaceholder reports whether value is an awssm:// secret reference.
func IsPlaceholder(value string) bool {
	return secretsinit.IsPlaceholder(value)
}

// Resolve resolves an awssm:// placeholder to its secret value.
//
// Formats:
//
//	awssm://<secret-name>        → raw secret string value
//	awssm://<secret-name>#<key>  → JSON-parsed value at <key>
//
// context.Context is the first argument as required by the prompt.
func (r *Resolver) Resolve(ctx context.Context, placeholder string) (string, error) {
	// Start an OTel span for each resolution so we can trace secret fetch latency.
	tracer := otel.Tracer(tracerName)
	ctx, span := tracer.Start(ctx, "resolver.Resolve")
	defer span.End()

	secretName, key, hasKey, parseErr := secretsinit.ParsePlaceholder(placeholder)
	if parseErr != nil {
		span.RecordError(parseErr)
		span.SetStatus(codes.Error, parseErr.Error())
		return "", parseErr
	}

	span.SetAttributes(attribute.String("secret.name", secretName))

	raw, err := r.fetchRaw(ctx, secretName)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		r.metrics.SecretResolutionsTotal.WithLabelValues("error").Inc()
		return "", err
	}

	if !hasKey {
		return raw, nil
	}

	val, err := secretsinit.ExtractJSONKey(raw, secretName, key)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		r.metrics.SecretResolutionsTotal.WithLabelValues("error").Inc()
		return "", err
	}

	span.SetStatus(codes.Ok, "")
	return val, nil
}

// fetchRaw retrieves the raw secret string through three layers:
//  1. requestCache — per-request, deduplicates within a single pod admission
//  2. sharedCache + singleflight — TTL-based with coalesced concurrent fetches
//  3. Secrets Manager API — only called once per cache miss, even under thundering herd
func (r *Resolver) fetchRaw(ctx context.Context, secretName string) (string, error) {
	// Layer 1: per-request cache.
	if cached, ok := r.requestCache[secretName]; ok {
		r.log.Debug("resolver: request cache hit", zap.String("secret", secretName))
		r.metrics.SecretResolutionsTotal.WithLabelValues("cache_hit").Inc()
		return cached, nil
	}

	// Layer 2: shared cache with singleflight coalescing.
	val, err := r.sharedCache.GetOrFetch(secretName, func() (string, error) {
		r.log.Debug("resolver: fetching from Secrets Manager", zap.String("secret", secretName))

		start := time.Now()
		out, err := r.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretName),
		})
		r.metrics.SecretResolutionDurationSeconds.Observe(time.Since(start).Seconds())

		if err != nil {
			return "", fmt.Errorf("resolver: failed to fetch secret %q: %w", secretName, err)
		}

		if out.SecretString == nil {
			return "", fmt.Errorf("resolver: secret %q has no string value (binary secrets are not supported)", secretName)
		}

		r.metrics.SecretResolutionsTotal.WithLabelValues("fetched").Inc()
		return *out.SecretString, nil
	})
	if err != nil {
		return "", err
	}

	r.requestCache[secretName] = val
	r.metrics.SecretResolutionsTotal.WithLabelValues("cache_hit").Inc()
	return val, nil
}

