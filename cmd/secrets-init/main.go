// secrets-init resolves awssm:// environment variable placeholders at container
// startup, then exec's the original application binary with the resolved values.
//
// Modes:
//
//	secrets-init --copy-to /secretsinit/secrets-init   → copy self to path and exit
//	secrets-init <command> [args...]               → resolve env vars, exec command
//
// Secret values exist only in process memory — never in the pod spec or etcd.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dannyvargas23/secrets-init-webhook/internal/secretsinit"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: secrets-init [--copy-to <path> | <command> [args...]]")
	}

	if os.Args[1] == "--copy-to" {
		handleCopyMode()
		return
	}

	handleExecMode()
}

// handleCopyMode copies the binary to the given path (used by the init container).
func handleCopyMode() {
	if len(os.Args) < 3 {
		fatal("usage: secrets-init --copy-to <path>")
	}
	if err := secretsinit.CopyTo(os.Args[2]); err != nil {
		fatal(err.Error())
	}
}

// internalEnvVars are env vars injected by the webhook for secrets-init's own use.
// They are stripped before exec'ing the app — the app doesn't need them.
var internalEnvVars = []string{
	"SECRETSINIT_AWS_REGION",
	"SECRETSINIT_IGNORE_MISSING",
}

// injectedSSLCertPath is the CA cert path injected by the webhook.
// SSL_CERT_FILE is only stripped if it matches this value — the app may
// have set its own SSL_CERT_FILE pointing at a custom CA bundle.
const injectedSSLCertPath = "/secretsinit/secrets-init.ca-certificates.crt"

// handleExecMode resolves awssm:// env vars, then replaces this process with the command.
func handleExecMode() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	envMap := collectEnv()
	envMap = resolveSecrets(ctx, envMap)
	stripInternalEnvVars(envMap)

	env := make([]string, 0, len(envMap))
	for k, v := range envMap {
		env = append(env, k+"="+v)
	}

	if err := secretsinit.Exec(os.Args[1:], env); err != nil {
		fatal(err.Error())
	}
}

// stripInternalEnvVars removes webhook-injected env vars from the map
// so they are not leaked to the application process.
func stripInternalEnvVars(envMap map[string]string) {
	for _, key := range internalEnvVars {
		delete(envMap, key)
	}
	// Only strip SSL_CERT_FILE if it's the one we injected.
	if envMap["SSL_CERT_FILE"] == injectedSSLCertPath {
		delete(envMap, "SSL_CERT_FILE")
	}
}

// resolveRegion returns the AWS region to use for Secrets Manager.
// Priority: SECRETSINIT_AWS_REGION (injected by webhook) > AWS_REGION > AWS_DEFAULT_REGION.
func resolveRegion(envMap map[string]string) string {
	if r := envMap["SECRETSINIT_AWS_REGION"]; r != "" {
		return r
	}
	if r := envMap["AWS_REGION"]; r != "" {
		return r
	}
	return envMap["AWS_DEFAULT_REGION"]
}

// collectEnv reads all current environment variables into a map.
func collectEnv() map[string]string {
	envMap := make(map[string]string)
	for _, e := range os.Environ() {
		k, v, _ := strings.Cut(e, "=")
		envMap[k] = v
	}
	return envMap
}

// awsCredentialEnvVars are the env vars the AWS SDK checks for static credentials.
// These must be unset from the process environment before creating the SM client
// so that Pod Identity (or IRSA/instance role) is used instead of any app-specific
// credentials the container may have.
var awsCredentialEnvVars = []string{
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
}

// resolveSecrets resolves any awssm:// placeholders in the env map.
// Returns the original map unchanged if no placeholders are found.
func resolveSecrets(ctx context.Context, envMap map[string]string) map[string]string {
	hasPlaceholders := false
	for _, v := range envMap {
		if secretsinit.IsPlaceholder(v) {
			hasPlaceholders = true
			break
		}
	}

	if !hasPlaceholders {
		return envMap
	}

	region := resolveRegion(envMap)

	// Unset static AWS credentials from the process environment so the SDK
	// credential chain falls through to Pod Identity / IRSA / instance role.
	// The original values are preserved in envMap and passed to the app via Exec.
	for _, key := range awsCredentialEnvVars {
		os.Unsetenv(key)
	}

	client, err := secretsinit.NewSMClient(ctx, region)
	if err != nil {
		fatal("failed to create AWS client: " + err.Error())
	}

	opts := secretsinit.ResolveOptions{
		IgnoreMissing: envMap["SECRETSINIT_IGNORE_MISSING"] == "true",
	}

	resolved, err := secretsinit.ResolveAll(ctx, client, envMap, opts)
	if err != nil {
		fatal("failed to resolve secrets: " + err.Error())
	}
	return resolved
}

// fatal logs a JSON error to stderr and exits with code 1.
func fatal(msg string) {
	entry := map[string]string{
		"level":  "error",
		"msg":    msg,
		"caller": "secrets-init",
		"ts":     time.Now().UTC().Format(time.RFC3339Nano),
	}
	_ = json.NewEncoder(os.Stderr).Encode(entry)
	fmt.Fprintln(os.Stderr, "secrets-init: "+msg)
	os.Exit(1)
}
