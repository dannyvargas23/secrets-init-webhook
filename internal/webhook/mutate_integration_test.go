package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/dannyvargas23/secrets-init-webhook/internal/config"
	"github.com/dannyvargas23/secrets-init-webhook/internal/observability"
	"github.com/dannyvargas23/secrets-init-webhook/internal/registry"
)

const (
	testMutatePath  = "/mutate"
	testContentType = "Content-Type"
	testJSONType    = "application/json"
	testInjectKey   = "secretsinit.io/inject"
)

func newTestServer() *Server {
	cfg := &config.Config{
		SecretsInitImage: "test-image:latest",
		AWSRegion:        "us-east-1",
	}
	reg := prometheus.NewRegistry()
	return &Server{
		cfg:       cfg,
		log:       zap.NewNop(),
		metrics:   observability.NewMetrics(reg),
		regClient: registry.NewClientWithECR(nil, nil, zap.NewNop()),
	}
}

func buildAdmissionReview(pod *corev1.Pod) []byte {
	raw, _ := json.Marshal(pod)
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       "test-uid",
			Namespace: "default",
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
	body, _ := json.Marshal(review)
	return body
}

func TestMutateInitContainerMode(t *testing.T) {
	t.Parallel()

	s := newTestServer()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-pod",
			Namespace:   "default",
			Annotations: map[string]string{testInjectKey: "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Image:   "myapp:latest",
				Command: []string{"/app"},
				Env:     []corev1.EnvVar{{Name: "SECRET", Value: "awssm:prod/config#KEY"}},
			}},
		},
	}

	handler := s.handleMutate()
	req := httptest.NewRequest(http.MethodPost, testMutatePath, bytes.NewReader(buildAdmissionReview(pod)))
	req.Header.Set(testContentType, testJSONType)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var review admissionv1.AdmissionReview
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &review))
	assert.True(t, review.Response.Allowed)
	assert.NotNil(t, review.Response.Patch)
	assert.Equal(t, "test-uid", string(review.Response.UID))
}

func TestMutateSkipAnnotation(t *testing.T) {
	t.Parallel()

	s := newTestServer()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{testInjectKey: "skip"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Command: []string{"/app"}}},
		},
	}

	handler := s.handleMutate()
	req := httptest.NewRequest(http.MethodPost, testMutatePath, bytes.NewReader(buildAdmissionReview(pod)))
	req.Header.Set(testContentType, testJSONType)
	rec := httptest.NewRecorder()

	handler(rec, req)

	var review admissionv1.AdmissionReview
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &review))
	assert.True(t, review.Response.Allowed)
	assert.Nil(t, review.Response.Patch, "skip annotation should produce no patch")
}

func TestMutateNoAnnotation(t *testing.T) {
	t.Parallel()

	s := newTestServer()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Command: []string{"/app"}}},
		},
	}

	handler := s.handleMutate()
	req := httptest.NewRequest(http.MethodPost, testMutatePath, bytes.NewReader(buildAdmissionReview(pod)))
	req.Header.Set(testContentType, testJSONType)
	rec := httptest.NewRecorder()

	handler(rec, req)

	var review admissionv1.AdmissionReview
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &review))
	assert.True(t, review.Response.Allowed)
	assert.Nil(t, review.Response.Patch)
}

func TestMutateRejectsNonPost(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	handler := s.handleMutate()

	req := httptest.NewRequest(http.MethodGet, testMutatePath, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestMutateRejectsWrongContentType(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	handler := s.handleMutate()

	req := httptest.NewRequest(http.MethodPost, testMutatePath, bytes.NewReader([]byte("{}")))
	req.Header.Set(testContentType, "text/plain")
	rec := httptest.NewRecorder()

	handler(rec, req)
	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
}

func TestMutateRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	handler := s.handleMutate()

	req := httptest.NewRequest(http.MethodPost, testMutatePath, bytes.NewReader([]byte("not json")))
	req.Header.Set(testContentType, testJSONType)
	rec := httptest.NewRecorder()

	handler(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMutateRejectsNilRequest(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	handler := s.handleMutate()

	review := admissionv1.AdmissionReview{Request: nil}
	body, _ := json.Marshal(review)

	req := httptest.NewRequest(http.MethodPost, testMutatePath, bytes.NewReader(body))
	req.Header.Set(testContentType, testJSONType)
	rec := httptest.NewRecorder()

	handler(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMutateContextTimeout(t *testing.T) {
	t.Parallel()

	s := newTestServer()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{testInjectKey: "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Image:   "myapp:latest",
				Command: []string{"/app"},
				Env:     []corev1.EnvVar{{Name: "SECRET", Value: "awssm:prod/config#KEY"}},
			}},
		},
	}

	handler := s.handleMutate()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(1 * time.Millisecond) // ensure context is expired

	req := httptest.NewRequest(http.MethodPost, testMutatePath, bytes.NewReader(buildAdmissionReview(pod))).WithContext(ctx)
	req.Header.Set(testContentType, testJSONType)
	rec := httptest.NewRecorder()

	handler(rec, req)
	// Should still return 200 — the webhook itself doesn't timeout,
	// it just passes the context to the injector which may handle it.
	assert.Equal(t, http.StatusOK, rec.Code)
}
