package webhook_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dannyvargas23/secrets-init-webhook/internal/webhook"
)

const testInjectAnnotation = "secretsinit.io/inject"

func TestShouldMutate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		annotations map[string]string
		want        bool
	}{
		{
			name:        "annotation present and true",
			annotations: map[string]string{testInjectAnnotation: "true"},
			want:        true,
		},
		{
			name:        "annotation present but false",
			annotations: map[string]string{testInjectAnnotation: "false"},
			want:        false,
		},
		{
			name:        "annotation absent",
			annotations: map[string]string{},
			want:        false,
		},
		{
			name:        "annotation present but wrong value",
			annotations: map[string]string{testInjectAnnotation: "yes"},
			want:        false,
		},
		{
			name:        "nil annotations map",
			annotations: nil,
			want:        false,
		},
		{
			name:        "other annotations present but inject annotation absent",
			annotations: map[string]string{"app.kubernetes.io/name": "myapp", "prometheus.io/scrape": "true"},
			want:        false,
		},
		{
			name:        "inject annotation present alongside other annotations",
			annotations: map[string]string{"app.kubernetes.io/name": "myapp", testInjectAnnotation: "true"},
			want:        true,
		},
		{
			name:        "skip annotation returns false",
			annotations: map[string]string{testInjectAnnotation: "skip"},
			want:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Annotations: tc.annotations},
			}
			assert.Equal(t, tc.want, webhook.ShouldMutate(pod))
		})
	}
}

func TestShouldSkip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		annotations map[string]string
		want        bool
	}{
		{
			name:        "skip annotation returns true",
			annotations: map[string]string{testInjectAnnotation: "skip"},
			want:        true,
		},
		{
			name:        "true annotation returns false",
			annotations: map[string]string{testInjectAnnotation: "true"},
			want:        false,
		},
		{
			name:        "absent annotation returns false",
			annotations: nil,
			want:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Annotations: tc.annotations},
			}
			assert.Equal(t, tc.want, webhook.ShouldSkip(pod))
		})
	}
}
