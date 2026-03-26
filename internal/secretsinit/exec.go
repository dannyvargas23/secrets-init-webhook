package secretsinit

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Exec resolves the binary path and replaces the current process with it.
// The resolved environment is passed directly — the original process is gone after this call.
func Exec(args, env []string) error {
	if len(args) == 0 {
		return fmt.Errorf("secretsinit: no command specified")
	}

	binary, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("secretsinit: command %q not found: %w", args[0], err)
	}

	return syscall.Exec(binary, args, env)
}

// CopyTo copies the current binary and CA certificates to the given directory path.
// The binary is written as "secrets-init" and certs as "ca-certificates.crt".
// Both are needed because target containers (e.g., busybox, scratch) may lack CA certs.
func CopyTo(dst string) error {
	if err := copyFile(selfPath(), dst, 0o555); err != nil {
		return err
	}

	// Copy CA certificates so secrets-init can verify TLS in containers without certs.
	caCertSrc := findCACerts()
	if caCertSrc != "" {
		caCertDst := dst + ".ca-certificates.crt"
		if err := copyFile(caCertSrc, caCertDst, 0o444); err != nil {
			return fmt.Errorf("secretsinit: failed to copy CA certs: %w", err)
		}
	}

	return nil
}

func selfPath() string {
	p, err := os.Executable()
	if err != nil {
		return "/secrets-init"
	}
	return p
}

func findCACerts() string {
	paths := []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func copyFile(src, dst string, perm os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("secretsinit: failed to read %q: %w", src, err)
	}
	if err := os.WriteFile(dst, data, perm); err != nil {
		return fmt.Errorf("secretsinit: failed to write %q: %w", dst, err)
	}
	return nil
}
