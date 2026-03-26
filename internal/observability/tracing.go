package observability

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const serviceName = "secrets-init-webhook"

// TracerShutdownFunc is a function that flushes and shuts down the tracer provider.
// The caller must invoke it (typically deferred in main) to ensure all spans are exported.
type TracerShutdownFunc func(ctx context.Context) error

// SetupTracing initialises the OpenTelemetry tracer provider with an OTLP gRPC exporter.
//
// Why OTLP gRPC: it is the canonical OTel export protocol, supported by all major
// collectors (Datadog agent, OpenTelemetry Collector, Jaeger, Tempo). Using the
// contrib otelhttp middleware automatically instruments all HTTP handlers.
//
// If endpoint is empty, a no-op tracer is installed so the app runs without tracing
// — useful in local development where no collector is available.
func SetupTracing(ctx context.Context, endpoint string) (TracerShutdownFunc, error) {
	if endpoint == "" {
		// No collector configured — install a no-op provider so otel calls are safe.
		otel.SetTracerProvider(otel.GetTracerProvider())
		return func(_ context.Context) error { return nil }, nil
	}

	conn, err := grpc.NewClient(endpoint,
		// insecure is acceptable here because the collector is in-cluster (pod-to-pod).
		// For cross-cluster or external collectors, use credentials.NewTLS.
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: failed to connect to OTLP endpoint %q: %w", endpoint, err)
	}

	exporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("tracing: failed to create OTLP exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
		),
		resource.WithFromEnv(),    // picks up OTEL_RESOURCE_ATTRIBUTES
		resource.WithProcess(),    // adds process metadata
		resource.WithOS(),         // adds OS metadata
		resource.WithContainer(),  // adds container metadata if available
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: failed to create resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// Register as the global provider so otelhttp middleware and otel.Tracer() calls work.
	otel.SetTracerProvider(tp)

	// W3C TraceContext + Baggage propagation — standard for inter-service tracing.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}
