package webhook

import (
	corev1 "k8s.io/api/core/v1"
)

const injectAnnotation = "secretsinit.io/inject"

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
