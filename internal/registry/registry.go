// Package registry provides container image config lookup for discovering
// ENTRYPOINT and CMD when they are not specified in the pod spec.
package registry

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/google/go-containerregistry/pkg/authn"
	kc "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// ImageConfig holds the entrypoint and command from a container image.
type ImageConfig struct {
	Entrypoint []string
	Cmd        []string
}

// ECRClient abstracts the ECR API for testing.
type ECRClient interface {
	GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

// Client fetches image configs from container registries.
type Client struct {
	k8s       kubernetes.Interface
	ecrClient ECRClient
	mu        sync.RWMutex
	cache     map[string]*ImageConfig
	log       *zap.Logger
}

// NewClient creates a registry client.
// If k8sClient is nil, falls back to the default keychain (no imagePullSecrets support).
// Initialises the ECR client using the AWS SDK v2 default credential chain,
// which supports EKS Pod Identity without requiring IMDS access.
func NewClient(ctx context.Context, k8sClient kubernetes.Interface, log *zap.Logger) (*Client, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("registry: failed to load AWS config: %w", err)
	}

	return &Client{
		k8s:       k8sClient,
		ecrClient: ecr.NewFromConfig(awsCfg),
		cache:     make(map[string]*ImageConfig),
		log:       log,
	}, nil
}

// NewClientWithECR creates a registry client with a custom ECR client (for testing).
func NewClientWithECR(k8sClient kubernetes.Interface, ecrClient ECRClient, log *zap.Logger) *Client {
	return &Client{
		k8s:       k8sClient,
		ecrClient: ecrClient,
		cache:     make(map[string]*ImageConfig),
		log:       log,
	}
}

// GetImageConfig fetches the ENTRYPOINT and CMD for the given image reference.
// Uses k8schain for authentication (same credentials as kubelet uses to pull images).
// Results are cached by image reference.
func (c *Client) GetImageConfig(ctx context.Context, imageRef, namespace string, imagePullSecrets []corev1.LocalObjectReference) (*ImageConfig, error) {
	if cfg := c.getFromCache(imageRef); cfg != nil {
		return cfg, nil
	}

	c.log.Debug("registry: fetching image config", zap.String("image", imageRef))

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("registry: failed to parse image reference %q: %w", imageRef, err)
	}

	keychain, err := c.buildKeychain(ctx, namespace, imagePullSecrets)
	if err != nil {
		return nil, fmt.Errorf("registry: failed to build keychain: %w", err)
	}

	desc, err := remote.Get(ref, remote.WithAuthFromKeychain(keychain))
	if err != nil {
		return nil, fmt.Errorf("registry: failed to fetch image %q: %w", imageRef, err)
	}

	img, err := resolveImage(desc, imageRef)
	if err != nil {
		return nil, err
	}

	cfgFile, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("registry: failed to get config for image %q: %w", imageRef, err)
	}

	imgCfg := &ImageConfig{
		Entrypoint: cfgFile.Config.Entrypoint,
		Cmd:        cfgFile.Config.Cmd,
	}

	c.putInCache(imageRef, imgCfg)

	c.log.Debug("registry: fetched image config",
		zap.String("image", imageRef),
		zap.Strings("entrypoint", imgCfg.Entrypoint),
		zap.Strings("cmd", imgCfg.Cmd),
	)

	return imgCfg, nil
}

// sdkECRHelper implements the docker credentials Helper interface using AWS SDK v2.
// Unlike amazon-ecr-credential-helper, this uses the SDK default credential chain
// which supports EKS Pod Identity (169.254.170.23) without needing IMDS access.
type sdkECRHelper struct {
	client ECRClient
}

// Get returns ECR credentials for the given server URL.
// Only returns credentials for ECR registries (*.ecr.*.amazonaws.com).
// Returns empty for all other registries so the DefaultKeychain handles them.
func (h *sdkECRHelper) Get(serverURL string) (string, string, error) {
	if !strings.Contains(serverURL, ".ecr.") || !strings.Contains(serverURL, ".amazonaws.com") {
		return "", "", fmt.Errorf("not an ECR registry: %s", serverURL)
	}

	ctx := context.Background()
	out, err := h.client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return "", "", fmt.Errorf("ecr: failed to get authorization token: %w", err)
	}

	for _, auth := range out.AuthorizationData {
		if auth.AuthorizationToken == nil {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(*auth.AuthorizationToken)
		if err != nil {
			return "", "", fmt.Errorf("ecr: failed to decode authorization token: %w", err)
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) == 2 {
			return parts[0], parts[1], nil
		}
	}

	return "", "", fmt.Errorf("ecr: no authorization data returned")
}

// buildKeychain creates a keychain that uses k8schain (same as kubelet) with
// fallback to SDK-based ECR auth and the default keychain.
func (c *Client) buildKeychain(ctx context.Context, namespace string, imagePullSecrets []corev1.LocalObjectReference) (authn.Keychain, error) {
	var keychains []authn.Keychain

	if c.k8s != nil {
		var secretNames []string
		for _, s := range imagePullSecrets {
			secretNames = append(secretNames, s.Name)
		}

		k8sKeychain, err := kc.New(ctx, c.k8s, kc.Options{
			Namespace:          namespace,
			ImagePullSecrets:   secretNames,
			ServiceAccountName: kc.NoServiceAccount,
		})
		if err != nil {
			return nil, err
		}
		keychains = append(keychains, k8sKeychain)
	}

	if c.ecrClient != nil {
		keychains = append(keychains, authn.NewKeychainFromHelper(&sdkECRHelper{client: c.ecrClient}))
	}

	keychains = append(keychains, authn.DefaultKeychain)
	return authn.NewMultiKeychain(keychains...), nil
}

func (c *Client) getFromCache(imageRef string) *ImageConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if cfg, ok := c.cache[imageRef]; ok {
		return cfg
	}
	return nil
}

func (c *Client) putInCache(imageRef string, cfg *ImageConfig) {
	c.mu.Lock()
	c.cache[imageRef] = cfg
	c.mu.Unlock()
}

// resolveImage handles both single-arch images and multi-arch indexes.
func resolveImage(desc *remote.Descriptor, imageRef string) (v1.Image, error) {
	if !desc.MediaType.IsIndex() {
		return desc.Image()
	}
	return resolveFromIndex(desc, imageRef)
}

// resolveFromIndex selects the linux/amd64 image from a multi-arch index.
func resolveFromIndex(desc *remote.Descriptor, imageRef string) (v1.Image, error) {
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("registry: failed to get image index for %q: %w", imageRef, err)
	}

	idxManifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("registry: failed to get index manifest for %q: %w", imageRef, err)
	}

	for _, m := range idxManifest.Manifests {
		if m.Platform != nil && m.Platform.OS == "linux" && m.Platform.Architecture == "amd64" {
			return idx.Image(m.Digest)
		}
	}

	if len(idxManifest.Manifests) > 0 {
		return idx.Image(idxManifest.Manifests[0].Digest)
	}

	return nil, fmt.Errorf("registry: image index for %q has no manifests", imageRef)
}
