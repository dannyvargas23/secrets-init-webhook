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
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/dannyvargas23/secrets-init-webhook/internal/registry"
	"github.com/dannyvargas23/secrets-init-webhook/internal/webhook"
)

const (
	testSecretsInitImage = "123456.dkr.ecr.us-east-1.amazonaws.com/secrets-init-vol:latest"
	testSecretsInitPath  = "/secretsinit/secrets-init"
	testPlaceholder      = "awssm:prod/config#KEY"
	testInjectAnno       = "secretsinit.io/inject"
)

func runInjectionPatch(t *testing.T, pod *corev1.Pod) ([]map[string]any, error) {
	t.Helper()
	return runInjectionPatchWithCfg(t, pod, webhook.InjectorConfig{Image: testSecretsInitImage, AWSRegion: "us-east-1"})
}

func runInjectionPatchWithCfg(t *testing.T, pod *corev1.Pod, cfg webhook.InjectorConfig) ([]map[string]any, error) {
	t.Helper()
	regClient := registry.NewClientWithECR(nil, nil, zap.NewNop())
	patch, err := webhook.BuildInjectionPatch(context.Background(), pod, cfg, regClient, zap.NewNop())
	if err != nil {
		return nil, err
	}
	if patch == nil {
		return nil, nil
	}
	var ops []map[string]any
	require.NoError(t, json.Unmarshal(patch, &ops))
	return ops, nil
}

func findOp(ops []map[string]any, opType, path string) map[string]any {
	for _, op := range ops {
		if op["op"] == opType && op["path"] == path {
			return op
		}
	}
	return nil
}

func TestInjectionPatchRewritesCommand(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Image:   "myapp:latest",
				Command: []string{"/app"},
				Args:    []string{"--port=8080"},
				Env: []corev1.EnvVar{
					{Name: "DB_PASSWORD", Value: "awssm:prod/myapp/config#DB_PASSWORD"},
					{Name: "LOG_LEVEL", Value: "info"},
				},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(ops), 5)

	cmdOp := findOp(ops, "replace", "/spec/containers/0/command")
	require.NotNil(t, cmdOp, "expected command replacement op")
	cmd := cmdOp["value"].([]any)
	assert.Equal(t, testSecretsInitPath, cmd[0])

	argsOp := findOp(ops, "replace", "/spec/containers/0/args")
	require.NotNil(t, argsOp, "expected args replacement op")
	args := argsOp["value"].([]any)
	assert.Equal(t, "/app", args[0])
	assert.Equal(t, "--port=8080", args[1])
}

func TestInjectionPatchNoPlaceholders(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Command: []string{"/app"},
				Env:     []corev1.EnvVar{{Name: "LOG_LEVEL", Value: "info"}},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)
	assert.Nil(t, ops)
}

func TestInjectionPatchMissingCommandTriggersRegistryLookup(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nonexistent.example.com/myapp:latest",
				Env:   []corev1.EnvVar{{Name: "DB_PASSWORD", Value: testPlaceholder}},
			}},
		},
	}

	_, err := runInjectionPatch(t, pod)
	require.Error(t, err)
	assert.ErrorContains(t, err, "image config lookup failed")
}

func TestInjectionPatchSkipsContainersWithoutPlaceholders(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "app",
					Command: []string{"/app"},
					Env:     []corev1.EnvVar{{Name: "DB_PASSWORD", Value: testPlaceholder}},
				},
				{
					Name:    "sidecar",
					Command: []string{"/sidecar"},
					Env:     []corev1.EnvVar{{Name: "LOG_LEVEL", Value: "info"}},
				},
			},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)

	for _, op := range ops {
		path, ok := op["path"].(string)
		if ok {
			assert.NotContains(t, path, "/spec/containers/1/command")
			assert.NotContains(t, path, "/spec/containers/1/args")
		}
	}
}

func TestInjectionPatchAlreadyMutated(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{Name: "secrets-init-vol"}},
			Containers: []corev1.Container{{
				Name:    "app",
				Command: []string{"/app"},
				Env:     []corev1.EnvVar{{Name: "DB_PASSWORD", Value: testPlaceholder}},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)
	assert.Nil(t, ops, "already-mutated pod should return nil patch")
}

func TestInjectionPatchInitContainerWithPlaceholders(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:    "migrate",
				Command: []string{"/migrate"},
				Env:     []corev1.EnvVar{{Name: "DB_PASSWORD", Value: testPlaceholder}},
			}},
			Containers: []corev1.Container{{
				Name:    "app",
				Command: []string{"/app"},
				Env:     []corev1.EnvVar{{Name: "LOG_LEVEL", Value: "info"}},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)
	require.NotNil(t, ops)

	// The init container should be wrapped (index 1 because copy-secrets-init is prepended at 0).
	cmdOp := findOp(ops, "replace", "/spec/initContainers/1/command")
	require.NotNil(t, cmdOp, "expected init container command replacement")
	cmd := cmdOp["value"].([]any)
	assert.Equal(t, testSecretsInitPath, cmd[0])
}

func TestInjectionPatchIgnoreMissingAnnotation(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				testInjectAnno:                 "true",
				"secretsinit.io/ignore-missing-secrets": "true",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Command: []string{"/app"},
				Env:     []corev1.EnvVar{{Name: "DB_PASSWORD", Value: testPlaceholder}},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)
	require.NotNil(t, ops)

	// Should inject SECRETSINIT_IGNORE_MISSING env var.
	found := false
	for _, op := range ops {
		if val, ok := op["value"].(map[string]any); ok {
			if val["name"] == "SECRETSINIT_IGNORE_MISSING" {
				found = true
			}
		}
	}
	assert.True(t, found, "expected SECRETSINIT_IGNORE_MISSING env var")
}

func TestInjectionPatchProbesMutation(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				testInjectAnno:        "true",
				"secretsinit.io/mutate-probes": "true",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Command: []string{"/app"},
				Env:     []corev1.EnvVar{{Name: "DB_PASSWORD", Value: testPlaceholder}},
				LivenessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						Exec: &corev1.ExecAction{Command: []string{"/healthcheck"}},
					},
				},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)
	require.NotNil(t, ops)

	probeOp := findOp(ops, "replace", "/spec/containers/0/livenessProbe/exec/command")
	require.NotNil(t, probeOp, "expected liveness probe command replacement")
	cmd := probeOp["value"].([]any)
	assert.Equal(t, testSecretsInitPath, cmd[0])
	assert.Equal(t, "/healthcheck", cmd[1])
}

func TestInjectionPatchHTTPProbeNotAffected(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				testInjectAnno:        "true",
				"secretsinit.io/mutate-probes": "true",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Command: []string{"/app"},
				Env:     []corev1.EnvVar{{Name: "DB_PASSWORD", Value: testPlaceholder}},
				LivenessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt(8080)},
					},
				},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)

	// No probe ops should exist for HTTP probes.
	probeOp := findOp(ops, "replace", "/spec/containers/0/livenessProbe/exec/command")
	assert.Nil(t, probeOp, "HTTP probe should not be modified")
}

func TestInjectionPatchEnvFromConfigMapRef(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Command: []string{"/app"},
				EnvFrom: []corev1.EnvFromSource{{
					ConfigMapRef: &corev1.ConfigMapEnvSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "myapp-env"},
					},
				}},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)
	require.NotNil(t, ops, "container with envFrom should be wrapped")

	cmdOp := findOp(ops, "replace", "/spec/containers/0/command")
	require.NotNil(t, cmdOp, "expected command replacement op")
}

func TestInjectionPatchEnvFromSecretRef(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Command: []string{"/app"},
				EnvFrom: []corev1.EnvFromSource{{
					SecretRef: &corev1.SecretEnvSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "myapp-secrets"},
					},
				}},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)
	require.NotNil(t, ops, "container with envFrom secretRef should be wrapped")
}

func TestInjectionPatchValueFrom(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Command: []string{"/app"},
				Env: []corev1.EnvVar{{
					Name: "DB_PASSWORD",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
							Key:                  "DB_PASSWORD",
						},
					},
				}},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)
	require.NotNil(t, ops, "container with valueFrom should be wrapped")
}

func TestInjectionPatchNoEnvAtAll(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Command: []string{"/app"},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)
	assert.Nil(t, ops, "container with no env should not be wrapped")
}

func TestInjectionPatchAlwaysInjectsSECRETSINITAWSRegion(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Image:   "myapp:latest",
				Command: []string{"/app"},
				Env: []corev1.EnvVar{
					{Name: "DB_PASSWORD", Value: testPlaceholder},
					{Name: "AWS_REGION", Value: "eu-west-1"}, // app's own region — should not affect secrets-init
				},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)
	require.NotNil(t, ops)

	// SECRETSINIT_AWS_REGION should always be injected with the webhook's configured region.
	found := false
	for _, op := range ops {
		if val, ok := op["value"].(map[string]any); ok {
			if val["name"] == "SECRETSINIT_AWS_REGION" {
				assert.Equal(t, "us-east-1", val["value"], "should use webhook config region")
				found = true
			}
		}
	}
	assert.True(t, found, "expected SECRETSINIT_AWS_REGION env var to be injected")
}

func TestInjectionPatchRegionAnnotationOverridesConfig(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"secretsinit.io/aws-region": "ap-southeast-1",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Command: []string{"/app"},
				Env:     []corev1.EnvVar{{Name: "DB_PASSWORD", Value: testPlaceholder}},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)
	require.NotNil(t, ops)

	// Annotation should override the webhook config region.
	for _, op := range ops {
		if val, ok := op["value"].(map[string]any); ok {
			if val["name"] == "SECRETSINIT_AWS_REGION" {
				assert.Equal(t, "ap-southeast-1", val["value"], "annotation should override config region")
				return
			}
		}
	}
	t.Fatal("expected SECRETSINIT_AWS_REGION env var to be injected")
}

func TestInjectionPatchContainerWithAWSCredsStillWrapped(t *testing.T) {
	t.Parallel()

	// Container has its own AWS credentials — webhook should still wrap it.
	// The secrets-init binary handles credential isolation at runtime.
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Command: []string{"/app"},
				Env: []corev1.EnvVar{
					{Name: "DB_PASSWORD", Value: testPlaceholder},
					{Name: "AWS_ACCESS_KEY_ID", Value: "AKIA..."},
					{Name: "AWS_SECRET_ACCESS_KEY", Value: "wJalr..."},
					{Name: "AWS_REGION", Value: "us-west-2"},
				},
			}},
		},
	}

	ops, err := runInjectionPatch(t, pod)
	require.NoError(t, err)
	require.NotNil(t, ops, "pod with AWS creds should still be wrapped")

	// SECRETSINIT_AWS_REGION should be present.
	found := false
	for _, op := range ops {
		if val, ok := op["value"].(map[string]any); ok {
			if val["name"] == "SECRETSINIT_AWS_REGION" {
				found = true
			}
		}
	}
	assert.True(t, found, "expected SECRETSINIT_AWS_REGION even when container has its own AWS creds")
}
