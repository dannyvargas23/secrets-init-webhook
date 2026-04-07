package registry_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dannyvargas23/secrets-init-webhook/internal/registry"
)

const testBusyboxImage = "busybox:latest"

func TestGetImageConfigPublicImage(t *testing.T) {
	t.Parallel()

	client := registry.NewClientWithECR(nil, nil, zap.NewNop())

	cfg, err := client.GetImageConfig(context.Background(), testBusyboxImage, "", nil)
	require.NoError(t, err)

	assert.Empty(t, cfg.Entrypoint)
	assert.Equal(t, []string{"sh"}, cfg.Cmd)
}

func TestGetImageConfigCachesResult(t *testing.T) {
	t.Parallel()

	client := registry.NewClientWithECR(nil, nil, zap.NewNop())
	ctx := context.Background()

	cfg1, err := client.GetImageConfig(ctx, testBusyboxImage, "", nil)
	require.NoError(t, err)

	cfg2, err := client.GetImageConfig(ctx, testBusyboxImage, "", nil)
	require.NoError(t, err)

	assert.Equal(t, cfg1, cfg2)
}

func TestGetImageConfigInvalidImage(t *testing.T) {
	t.Parallel()

	client := registry.NewClientWithECR(nil, nil, zap.NewNop())

	_, err := client.GetImageConfig(context.Background(), "nonexistent.example.com/no-such-image:latest", "", nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to fetch image")
}

func TestGetImageConfigDistrolessNode(t *testing.T) {
	t.Parallel()

	client := registry.NewClientWithECR(nil, nil, zap.NewNop())

	cfg, err := client.GetImageConfig(context.Background(), "gcr.io/distroless/nodejs18-debian12:latest", "", nil)
	require.NoError(t, err)

	assert.Contains(t, cfg.Entrypoint[0], "node")
	assert.Empty(t, cfg.Cmd)
}

func TestGetImageConfigMultiArch(t *testing.T) {
	t.Parallel()

	client := registry.NewClientWithECR(nil, nil, zap.NewNop())

	cfg, err := client.GetImageConfig(context.Background(), "nginx:latest", "", nil)
	require.NoError(t, err)

	require.NotEmpty(t, cfg.Entrypoint)
	require.NotEmpty(t, cfg.Cmd)
}
