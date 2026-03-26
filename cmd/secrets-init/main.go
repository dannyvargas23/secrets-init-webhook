// secrets-init resolves awssm:// environment variable placeholders at container
// startup, then exec's the original application binary with the resolved values.
//
// Modes:
//
//	secrets-init --copy-to /sevaro/secrets-init   → copy self to path and exit
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

// handleExecMode resolves awssm:// env vars, then replaces this process with the command.
func handleExecMode() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	envMap := collectEnv()
	envMap = resolveSecrets(ctx, envMap)

	env := make([]string, 0, len(envMap))
	for k, v := range envMap {
		env = append(env, k+"="+v)
	}

	if err := secretsinit.Exec(os.Args[1:], env); err != nil {
		fatal(err.Error())
	}
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

	region := envMap["AWS_REGION"]
	if region == "" {
		region = envMap["AWS_DEFAULT_REGION"]
	}

	client, err := secretsinit.NewSMClient(ctx, region)
	if err != nil {
		fatal("failed to create AWS client: " + err.Error())
	}

	opts := secretsinit.ResolveOptions{
		IgnoreMissing: envMap["SEVARO_IGNORE_MISSING_SECRETS"] == "true",
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
