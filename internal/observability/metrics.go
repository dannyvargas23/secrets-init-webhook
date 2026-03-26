// Package observability sets up Prometheus metrics and OpenTelemetry tracing.
//
// Why a dedicated package: the prompt requires proactive observability hooks on
// any service code. Isolating observability setup here keeps the webhook package
// focused on admission logic and makes metrics/tracing easy to test independently.
package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const namespace = "secrets_init_webhook"

// Metrics holds all Prometheus metrics for the webhook.
// Using promauto registers metrics automatically with the default registry.
type Metrics struct {
	// AdmissionRequestsTotal counts admission requests by namespace and result.
	// result label values: "allowed", "denied", "error"
	AdmissionRequestsTotal *prometheus.CounterVec

	// AdmissionDurationSeconds tracks the duration of each admission request.
	AdmissionDurationSeconds *prometheus.HistogramVec

	// SecretResolutionsTotal counts secret resolution attempts by result.
	// result label values: "cache_hit", "fetched", "error"
	SecretResolutionsTotal *prometheus.CounterVec

	// SecretResolutionDurationSeconds tracks the duration of each Secrets Manager API call.
	SecretResolutionDurationSeconds prometheus.Histogram
}

// NewMetrics constructs and registers all webhook Prometheus metrics.
// Registering with a custom registry (rather than prometheus.DefaultRegisterer)
// makes unit tests safe — each test can use its own registry without global state conflicts.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	factory := promauto.With(reg)

	return &Metrics{
		AdmissionRequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "admission_requests_total",
				Help:      "Total number of admission requests processed, by namespace and result.",
			},
			[]string{"namespace", "result"},
		),

		AdmissionDurationSeconds: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "admission_duration_seconds",
				Help:      "Duration of admission request processing in seconds.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"result"},
		),

		SecretResolutionsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "secret_resolutions_total",
				Help:      "Total number of secret resolution attempts, by result (cache_hit, fetched, error).",
			},
			[]string{"result"},
		),

		SecretResolutionDurationSeconds: factory.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "secret_resolution_duration_seconds",
				Help:      "Duration of AWS Secrets Manager GetSecretValue API calls in seconds.",
				Buckets:   []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5},
			},
		),
	}
}
