package webhook

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"go.uber.org/zap"

	"github.com/dannyvargas23/secrets-init-webhook/internal/registry"
	"github.com/dannyvargas23/secrets-init-webhook/internal/secretsinit"
)

const (
	initVolumeName = "secrets-init"
	initMountPath  = "/secretsinit"
	initBinaryPath = "/secretsinit/secrets-init"
	initCACertPath = "/secretsinit/secrets-init.ca-certificates.crt"
	envAppendPath  = "/env/-"
)

// InjectorConfig holds configuration for init-container injection.
type InjectorConfig struct {
	Image string
}

// containerMutationOpts holds per-container mutation options parsed from pod annotations.
type containerMutationOpts struct {
	ignoreMissing    bool
	mutateProbes     bool
	regionOverride   string
	namespace        string
	imagePullSecrets []corev1.LocalObjectReference
}

// BuildInjectionPatch builds a JSON Patch that injects the secrets-init binary
// into the pod instead of resolving secrets server-side.
//
// The pod spec in etcd retains the awssm:// placeholders — secrets are
// resolved at container startup inside the target pod.
func BuildInjectionPatch(ctx context.Context, pod *corev1.Pod, cfg InjectorConfig, regClient *registry.Client, log *zap.Logger) ([]byte, error) {
	// Already-mutated detection: skip if the secrets-init volume is already present.
	if isAlreadyMutated(pod) {
		log.Debug("injector: pod already mutated, skipping")
		return nil, nil
	}

	// Read per-pod annotation overrides.
	if imgOverride := pod.Annotations["secretsinit.io/secret-init-image"]; imgOverride != "" {
		cfg.Image = imgOverride
	}

	containersMut := findContainersWithPlaceholders(pod.Spec.Containers)
	initContainersMut := findContainersWithPlaceholders(pod.Spec.InitContainers)

	if len(containersMut) == 0 && len(initContainersMut) == 0 {
		return nil, nil
	}

	// Check if ignore-missing-secrets is set.
	mutOpts := containerMutationOpts{
		ignoreMissing:    pod.Annotations["secretsinit.io/ignore-missing-secrets"] == "true",
		mutateProbes:     pod.Annotations["secretsinit.io/mutate-probes"] == "true",
		regionOverride:   pod.Annotations["secretsinit.io/aws-region"],
		namespace:        pod.Namespace,
		imagePullSecrets: pod.Spec.ImagePullSecrets,
	}

	var ops []jsonPatchOp
	ops = append(ops, buildVolumeOps(pod)...)
	ops = append(ops, buildInitContainerOps(pod, cfg)...)

	// Wrap regular containers.
	for ci := range containersMut {
		containerOps, err := buildSingleContainerOps(ctx, pod.Spec.Containers[ci], ci, "containers", regClient, mutOpts, log)
		if err != nil {
			return nil, err
		}
		ops = append(ops, containerOps...)
	}

	// Wrap init containers (offset by 1 because we prepend copy-secrets-init).
	for ci := range initContainersMut {
		adjustedIdx := ci + 1
		containerOps, err := buildSingleContainerOps(ctx, pod.Spec.InitContainers[ci], adjustedIdx, "initContainers", regClient, mutOpts, log)
		if err != nil {
			return nil, err
		}
		ops = append(ops, containerOps...)
	}

	totalWrapped := len(containersMut) + len(initContainersMut)

	patch, err := json.Marshal(ops)
	if err != nil {
		return nil, fmt.Errorf("injector: failed to marshal JSON patch: %w", err)
	}

	log.Info("injector: patch built",
		zap.String("pod", pod.Name),
		zap.String("namespace", pod.Namespace),
		zap.Int("operations", len(ops)),
		zap.Int("containers_wrapped", totalWrapped),
	)

	return patch, nil
}

// isAlreadyMutated checks if the pod has already been mutated by the webhook.
func isAlreadyMutated(pod *corev1.Pod) bool {
	for _, v := range pod.Spec.Volumes {
		if v.Name == initVolumeName {
			return true
		}
	}
	return false
}

// findContainersNeedingMutation returns indices of containers that may have awssm: placeholders.
// A container needs wrapping if it has:
//   - direct env[].value with awssm: prefix
//   - envFrom (configMapRef/secretRef) — could contain placeholders
//   - env[].valueFrom (configMapKeyRef/secretKeyRef) — could reference a placeholder
func findContainersWithPlaceholders(containers []corev1.Container) map[int]bool {
	result := make(map[int]bool)
	for ci, container := range containers {
		// Direct env value placeholders.
		for _, env := range container.Env {
			if secretsinit.IsPlaceholder(env.Value) {
				result[ci] = true
				break
			}
		}
		if result[ci] {
			continue
		}
		// envFrom could contain placeholders from ConfigMaps/Secrets.
		if len(container.EnvFrom) > 0 {
			result[ci] = true
			continue
		}
		// valueFrom could reference a placeholder in a Secret/ConfigMap.
		for _, env := range container.Env {
			if env.ValueFrom != nil {
				result[ci] = true
				break
			}
		}
	}
	return result
}

// buildVolumeOps returns the patch op to add the shared tmpfs volume.
func buildVolumeOps(pod *corev1.Pod) []jsonPatchOp {
	vol := map[string]any{
		"name":     initVolumeName,
		"emptyDir": map[string]any{"medium": "Memory"},
	}

	if len(pod.Spec.Volumes) == 0 {
		return []jsonPatchOp{{Op: "add", Path: "/spec/volumes", Value: []any{vol}}}
	}
	return []jsonPatchOp{{Op: "add", Path: "/spec/volumes/-", Value: vol}}
}

// buildInitContainerOps returns the patch op to add the secrets-init copy init container.
func buildInitContainerOps(pod *corev1.Pod, cfg InjectorConfig) []jsonPatchOp {
	initContainer := map[string]any{
		"name":            "copy-secrets-init",
		"image":           cfg.Image,
		"imagePullPolicy": "IfNotPresent",
		"command":         []string{"/secrets-init", "--copy-to", initBinaryPath},
		"volumeMounts":    []map[string]any{{"name": initVolumeName, "mountPath": initMountPath}},
		"resources": map[string]any{
			"requests": map[string]string{"cpu": "10m", "memory": "16Mi"},
			"limits":   map[string]string{"cpu": "50m", "memory": "32Mi"},
		},
		"securityContext": map[string]any{
			"runAsNonRoot":             true,
			"readOnlyRootFilesystem":   true,
			"allowPrivilegeEscalation": false,
			"capabilities":             map[string]any{"drop": []string{"ALL"}},
		},
	}

	if len(pod.Spec.InitContainers) == 0 {
		return []jsonPatchOp{{Op: "add", Path: "/spec/initContainers", Value: []any{initContainer}}}
	}
	return []jsonPatchOp{{Op: "add", Path: "/spec/initContainers/0", Value: initContainer}}
}

// buildContainerOps returns patch ops for a single container: volumeMount + command rewrite.
// containerType is "containers" or "initContainers" for the JSON Patch path.
func buildSingleContainerOps(ctx context.Context, container corev1.Container, ci int, containerType string, regClient *registry.Client, opts containerMutationOpts, log *zap.Logger) ([]jsonPatchOp, error) {
	var ops []jsonPatchOp
	basePath := fmt.Sprintf("/spec/%s/%d", containerType, ci)

	// Add volumeMount for /secretsinit.
	mount := map[string]any{"name": initVolumeName, "mountPath": initMountPath, "readOnly": true}
	if len(container.VolumeMounts) == 0 {
		ops = append(ops, jsonPatchOp{Op: "add", Path: basePath + "/volumeMounts", Value: []any{mount}})
	} else {
		ops = append(ops, jsonPatchOp{Op: "add", Path: basePath + "/volumeMounts/-", Value: mount})
	}

	// Build original command + args.
	originalCmd := resolveOriginalCommand(ctx, container, regClient, opts, log)
	if originalCmd == nil {
		return nil, fmt.Errorf("injector: container %q has no command/args and image config lookup failed", container.Name)
	}

	cmdOp, argsOp := "replace", "replace"
	if len(container.Command) == 0 {
		cmdOp = "add"
	}
	if len(container.Args) == 0 {
		argsOp = "add"
	}

	ops = append(ops,
		jsonPatchOp{Op: cmdOp, Path: basePath + "/command", Value: []string{initBinaryPath}},
		jsonPatchOp{Op: argsOp, Path: basePath + "/args", Value: originalCmd},
	)

	// Set SSL_CERT_FILE for containers without CA certs.
	envPath := basePath + envAppendPath
	ops = append(ops, jsonPatchOp{
		Op:    "add",
		Path:  envPath,
		Value: map[string]any{"name": "SSL_CERT_FILE", "value": initCACertPath},
	})

	// Inject ignore-missing-secrets env var if annotation is set.
	if opts.ignoreMissing {
		ops = append(ops, jsonPatchOp{
			Op:    "add",
			Path:  envPath,
			Value: map[string]any{"name": "SEVARO_IGNORE_MISSING_SECRETS", "value": "true"},
		})
	}

	// Inject AWS_REGION override if annotation is set.
	if opts.regionOverride != "" {
		ops = append(ops, jsonPatchOp{
			Op:   "add",
			Path:  envPath,
			Value: map[string]any{"name": "AWS_REGION", "value": opts.regionOverride},
		})
	}

	// Wrap exec probe commands with secrets-init if requested.
	if opts.mutateProbes {
		ops = append(ops, buildProbeOps(container, basePath)...)
	}

	log.Info("injector: wrapping container with secrets-init",
		zap.String("container", container.Name),
		zap.String("type", containerType),
		zap.Strings("originalCmd", originalCmd),
	)

	return ops, nil
}

// buildProbeOps wraps exec probe commands with secrets-init.
func buildProbeOps(container corev1.Container, basePath string) []jsonPatchOp {
	var ops []jsonPatchOp

	if container.LivenessProbe != nil && container.LivenessProbe.Exec != nil {
		wrapped := append([]string{initBinaryPath}, container.LivenessProbe.Exec.Command...)
		ops = append(ops, jsonPatchOp{Op: "replace", Path: basePath + "/livenessProbe/exec/command", Value: wrapped})
	}
	if container.ReadinessProbe != nil && container.ReadinessProbe.Exec != nil {
		wrapped := append([]string{initBinaryPath}, container.ReadinessProbe.Exec.Command...)
		ops = append(ops, jsonPatchOp{Op: "replace", Path: basePath + "/readinessProbe/exec/command", Value: wrapped})
	}
	if container.StartupProbe != nil && container.StartupProbe.Exec != nil {
		wrapped := append([]string{initBinaryPath}, container.StartupProbe.Exec.Command...)
		ops = append(ops, jsonPatchOp{Op: "replace", Path: basePath + "/startupProbe/exec/command", Value: wrapped})
	}

	return ops
}

// resolveOriginalCommand returns the command the container should run.
//
// Kubernetes behavior:
//   - command set: overrides image ENTRYPOINT
//   - args set (no command): image ENTRYPOINT + pod args
//   - neither set: image ENTRYPOINT + image CMD
//   - both set: pod command + pod args
func resolveOriginalCommand(ctx context.Context, container corev1.Container, regClient *registry.Client, opts containerMutationOpts, log *zap.Logger) []string {
	if len(container.Command) > 0 {
		return append(container.Command, container.Args...)
	}

	imgCfg, err := regClient.GetImageConfig(ctx, container.Image, opts.namespace, opts.imagePullSecrets)
	if err != nil {
		log.Error("injector: image config lookup failed",
			zap.String("container", container.Name),
			zap.String("image", container.Image),
			zap.Error(err),
		)
		return nil
	}

	if len(imgCfg.Entrypoint) == 0 && len(container.Args) == 0 && len(imgCfg.Cmd) == 0 {
		log.Error("injector: image has no ENTRYPOINT or CMD",
			zap.String("container", container.Name),
			zap.String("image", container.Image),
		)
		return nil
	}

	// If pod has args, use ENTRYPOINT + pod args (K8s behavior: args override CMD).
	// If pod has no args, use ENTRYPOINT + image CMD.
	var cmd []string
	cmd = append(cmd, imgCfg.Entrypoint...)
	if len(container.Args) > 0 {
		cmd = append(cmd, container.Args...)
	} else {
		cmd = append(cmd, imgCfg.Cmd...)
	}

	log.Info("injector: resolved command from image config",
		zap.String("container", container.Name),
		zap.String("image", container.Image),
		zap.Strings("command", cmd),
	)
	return cmd
}
