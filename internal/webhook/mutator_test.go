package webhook_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dannyvargas23/secrets-init-webhook/internal/webhook"
)

const (
	testInjectAnnotation = "secretsinit.io/inject"
	testDBPasswordRef    = "awssm:prod/myapp/config#DB_PASSWORD"
)

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

func TestBuildPatch(t *testing.T) {
	t.Parallel()

	secrets := map[string]string{
		"prod/myapp/config": `{"DB_PASSWORD":"s3cr3t","DB_USER":"myapp"}`,
		"prod/myapp/token":  "plain-token",
	}

	tests := []struct {
		name     string
		pod      *corev1.Pod
		wantOps  int
		wantErr  string
		checkOps func(t *testing.T, ops []jsonPatchOpForTest)
	}{
		{
			name: "single container single placeholder",
			pod: podFixture([]corev1.EnvVar{
				{Name: "DB_PASSWORD", Value: testDBPasswordRef},
				{Name: "LOG_LEVEL", Value: "info"},
			}, nil),
			wantOps: 1,
			checkOps: func(t *testing.T, ops []jsonPatchOpForTest) {
				t.Helper()
				assert.Equal(t, "replace", ops[0].Op)
				assert.Equal(t, "/spec/containers/0/env/0/value", ops[0].Path)
				assert.Equal(t, "s3cr3t", ops[0].Value)
			},
		},
		{
			name: "multiple placeholders same secret — one API call",
			pod: podFixture([]corev1.EnvVar{
				{Name: "DB_PASSWORD", Value: testDBPasswordRef},
				{Name: "DB_USER", Value: "awssm:prod/myapp/config#DB_USER"},
			}, nil),
			wantOps: 2,
		},
		{
			name: "plain string secret no key",
			pod: podFixture([]corev1.EnvVar{
				{Name: "TOKEN", Value: "awssm:prod/myapp/token"},
			}, nil),
			wantOps: 1,
			checkOps: func(t *testing.T, ops []jsonPatchOpForTest) {
				t.Helper()
				assert.Equal(t, "plain-token", ops[0].Value)
			},
		},
		{
			name: "no placeholders returns nil patch",
			pod: podFixture([]corev1.EnvVar{
				{Name: "LOG_LEVEL", Value: "info"},
				{Name: "PORT", Value: "8080"},
			}, nil),
			wantOps: 0,
		},
		{
			name: "initContainer placeholders are patched",
			pod: podFixture(nil, []corev1.EnvVar{
				{Name: "DB_PASSWORD", Value: testDBPasswordRef},
			}),
			wantOps: 1,
			checkOps: func(t *testing.T, ops []jsonPatchOpForTest) {
				t.Helper()
				assert.Contains(t, ops[0].Path, "initContainers")
			},
		},
		{
			name: "unknown secret returns error and denies pod",
			pod: podFixture([]corev1.EnvVar{
				{Name: "X", Value: "awssm:prod/myapp/nonexistent#key"},
			}, nil),
			wantErr: "not found",
		},
		{
			name:    "empty pod spec returns nil patch",
			pod:     &corev1.Pod{},
			wantOps: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := newMock(secrets)
			resolver := newTestResolver(mock)

			patch, err := webhook.BuildPatch(context.Background(), tc.pod, resolver, zap.NewNop())

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)

			if tc.wantOps == 0 {
				assert.Nil(t, patch, "expected nil patch when no placeholders")
				return
			}

			var ops []jsonPatchOpForTest
			require.NoError(t, json.Unmarshal(patch, &ops))
			assert.Len(t, ops, tc.wantOps)

			if tc.checkOps != nil {
				tc.checkOps(t, ops)
			}
		})
	}
}

// jsonPatchOpForTest mirrors jsonPatchOp for unmarshalling in tests.
// The internal type is unexported; we unmarshal through this local mirror.
type jsonPatchOpForTest struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value"`
}

func podFixture(containerEnv, initContainerEnv []corev1.EnvVar) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-pod",
			Namespace:   "test-ns",
			Annotations: map[string]string{testInjectAnnotation: "true"},
		},
		Spec: corev1.PodSpec{},
	}
	if containerEnv != nil {
		pod.Spec.Containers = []corev1.Container{
			{Name: "app", Image: "myapp:latest", Env: containerEnv},
		}
	}
	if initContainerEnv != nil {
		pod.Spec.InitContainers = []corev1.Container{
			{Name: "init", Image: "busybox:latest", Env: initContainerEnv},
		}
	}
	return pod
}
