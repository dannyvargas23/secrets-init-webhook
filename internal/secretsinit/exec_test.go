package secretsinit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSelfPath(t *testing.T) {
	t.Parallel()

	path := selfPath()
	assert.NotEmpty(t, path, "selfPath should return the test binary path")
}

func TestFindCACerts(t *testing.T) {
	t.Parallel()

	// On most systems, at least one CA cert path exists.
	path := findCACerts()
	// May be empty on some CI systems, so just verify it doesn't panic.
	_ = path
}

func TestExecNoCommand(t *testing.T) {
	t.Parallel()

	err := Exec(nil, nil)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "no command specified")
}

func TestExecCommandNotFound(t *testing.T) {
	t.Parallel()

	err := Exec([]string{"nonexistent-binary-xyz"}, nil)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "not found")
}
