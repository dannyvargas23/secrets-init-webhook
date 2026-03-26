package webhook

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"go.uber.org/zap"
)

const injectAnnotation = "secretsinit.io/inject"

const modeAnnotation = "secretsinit.io/mode"

// jsonPatchOp represents a single RFC 6902 JSON Patch operation.
type jsonPatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// shouldMutate returns true only when the pod carries the explicit opt-in annotation.
// We check annotations (not labels) because annotations are for non-identifying
// metadata like operational flags, while labels are for selection/grouping.
func ShouldMutate(pod *corev1.Pod) bool {
	v := pod.Annotations[injectAnnotation]
	return v == "true"
}

// ShouldSkip returns true when the pod explicitly opts out of mutation.
func ShouldSkip(pod *corev1.Pod) bool {
	return pod.Annotations[injectAnnotation] == "skip"
}

// buildPatch scans all containers and initContainers for awssm:// placeholders,
// resolves each one via the Resolver, and returns a serialised RFC 6902 JSON Patch.
//
// Returns nil patch (no error) when no placeholders are found — callers must check for nil.
// Returns an error immediately if any placeholder fails to resolve — we never admit
// a pod with an unresolved secret reference, as silent empty values are harder to debug
// than an explicit admission denial.
//
// context.Context is the first argument as required by the prompt for all I/O-bound functions.
func BuildPatch(ctx context.Context, pod *corev1.Pod, resolver *Resolver, log *zap.Logger) ([]byte, error) {
	var ops []jsonPatchOp

	containerOps, err := scanContainers(ctx, pod.Spec.Containers, "containers", resolver, log)
	if err != nil {
		return nil, err
	}
	ops = append(ops, containerOps...)

	initOps, err := scanContainers(ctx, pod.Spec.InitContainers, "initContainers", resolver, log)
	if err != nil {
		return nil, err
	}
	ops = append(ops, initOps...)

	if len(ops) == 0 {
		return nil, nil
	}

	patch, err := json.Marshal(ops)
	if err != nil {
		return nil, fmt.Errorf("mutator: failed to marshal JSON patch: %w", err)
	}

	log.Info("mutator: patch built",
		zap.String("pod", pod.Name),
		zap.String("namespace", pod.Namespace),
		zap.Int("operations", len(ops)),
	)

	return patch, nil
}

// scanContainers iterates a container slice and builds replace patch ops for
// every env var whose value is an awssm:// placeholder.
func scanContainers(
	ctx context.Context,
	containers []corev1.Container,
	containerType string,
	resolver *Resolver,
	log *zap.Logger,
) ([]jsonPatchOp, error) {
	var ops []jsonPatchOp

	for ci, container := range containers {
		for ei, env := range container.Env {
			if !IsPlaceholder(env.Value) {
				continue
			}

			log.Debug("mutator: resolving placeholder",
				zap.String("container", container.Name),
				zap.String("env", env.Name),
			)

			resolved, err := resolver.Resolve(ctx, env.Value)
			if err != nil {
				return nil, fmt.Errorf("mutator: container %q env %q: %w", container.Name, env.Name, err)
			}

			ops = append(ops, jsonPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/spec/%s/%d/env/%d/value", containerType, ci, ei),
				Value: resolved,
			})
		}
	}

	return ops, nil
}
