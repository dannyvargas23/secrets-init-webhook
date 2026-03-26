package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.uber.org/zap"
)

// handleMutateWith returns an http.HandlerFunc for POST /mutate.
//
// The smClient is injected via closure — it is created once at server startup
// and reused across all requests. A fresh Resolver (with a fresh cache) is
// constructed per AdmissionReview request.
func (s *Server) handleMutateWith(smClient SecretsManagerClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Input validation — reject malformed requests before doing any work.
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			s.log.Warn("handler: unexpected Content-Type", zap.String("content_type", ct))
			http.Error(w, "expected Content-Type: application/json", http.StatusUnsupportedMediaType)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB — generous for a pod spec
		if err != nil {
			s.log.Error("handler: failed to read request body", zap.Error(err))
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}

		var review admissionv1.AdmissionReview
		if err := json.Unmarshal(body, &review); err != nil {
			s.log.Error("handler: failed to decode AdmissionReview", zap.Error(err))
			http.Error(w, "failed to decode AdmissionReview", http.StatusBadRequest)
			return
		}

		if review.Request == nil {
			s.log.Error("handler: AdmissionReview.Request is nil")
			http.Error(w, "AdmissionReview request is nil", http.StatusBadRequest)
			return
		}

		review.Response = s.mutate(r.Context(), review.Request, smClient)
		review.Response.UID = review.Request.UID

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(review); err != nil {
			s.log.Error("handler: failed to write response", zap.Error(err))
		}
	}
}

// mutate processes a single AdmissionRequest and returns the AdmissionResponse.
//
// Tracing: a span is started for the full mutate call. Child spans are created
// in resolver.Resolve for individual Secrets Manager calls, giving end-to-end
// visibility into where admission latency comes from.
//
// Metrics: admission result and duration are recorded regardless of outcome.
func (s *Server) mutate(ctx context.Context, req *admissionv1.AdmissionRequest, smClient SecretsManagerClient) *admissionv1.AdmissionResponse {
	tracer := otel.Tracer(tracerName)
	ctx, span := tracer.Start(ctx, "webhook.mutate")
	defer span.End()

	start := time.Now()

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		err = fmt.Errorf("handler: failed to decode pod: %w", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		s.metrics.AdmissionRequestsTotal.WithLabelValues(req.Namespace, "error").Inc()
		s.metrics.AdmissionDurationSeconds.WithLabelValues("error").Observe(time.Since(start).Seconds())
		return errorResponse(err)
	}

	log := s.log.With(
		zap.String("pod", pod.Name),
		zap.String("namespace", pod.Namespace),
		zap.String("uid", string(req.UID)),
	)

	span.SetAttributes(
		attribute.String("pod.name", pod.Name),
		attribute.String("pod.namespace", pod.Namespace),
	)

	if !ShouldMutate(&pod) || ShouldSkip(&pod) {
		log.Debug("handler: skipping — inject annotation absent or set to skip")
		s.metrics.AdmissionRequestsTotal.WithLabelValues(pod.Namespace, "allowed").Inc()
		s.metrics.AdmissionDurationSeconds.WithLabelValues("allowed").Observe(time.Since(start).Seconds())
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	log.Info("handler: mutating pod")

	// Determine mutation mode: per-pod annotation overrides server config.
	mode := s.cfg.MutationMode
	if override := pod.Annotations[modeAnnotation]; override != "" {
		mode = override
	}

	var patch []byte
	var err error

	switch mode {
	case "init-container":
		patch, err = BuildInjectionPatch(ctx, &pod, InjectorConfig{Image: s.cfg.SecretsInitImage}, s.regClient, log)
	default:
		// "direct" mode: resolve secrets server-side (values end up in pod spec/etcd).
		resolver := NewResolver(smClient, s.secretCache, s.metrics, log)
		patch, err = BuildPatch(ctx, &pod, resolver, log)
	}
	if err != nil {
		log.Error("handler: patch build failed", zap.Error(err))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		s.metrics.AdmissionRequestsTotal.WithLabelValues(pod.Namespace, "denied").Inc()
		s.metrics.AdmissionDurationSeconds.WithLabelValues("denied").Observe(time.Since(start).Seconds())
		return errorResponse(err)
	}

	if patch == nil {
		log.Info("handler: no placeholders found, passing through")
		s.metrics.AdmissionRequestsTotal.WithLabelValues(pod.Namespace, "allowed").Inc()
		s.metrics.AdmissionDurationSeconds.WithLabelValues("allowed").Observe(time.Since(start).Seconds())
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	span.SetStatus(codes.Ok, "")
	s.metrics.AdmissionRequestsTotal.WithLabelValues(pod.Namespace, "allowed").Inc()
	s.metrics.AdmissionDurationSeconds.WithLabelValues("allowed").Observe(time.Since(start).Seconds())

	pt := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{
		Allowed:   true,
		Patch:     patch,
		PatchType: &pt,
	}
}

// errorResponse returns a denial AdmissionResponse with the error message.
// Denying (rather than allowing with empty values) surfaces the problem immediately
// at kubectl apply time rather than causing a silent runtime failure inside the pod.
func errorResponse(err error) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		},
	}
}
