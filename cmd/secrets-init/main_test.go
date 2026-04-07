package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRegionUSEast1      = "us-east-1"
	testRegionUSWest2      = "us-west-2"
	testRegionEUWest1      = "eu-west-1"
	testRegionAPSoutheast1 = "ap-southeast-1"
)

func TestCollectEnv(t *testing.T) {
	t.Setenv("TEST_COLLECT_ENV_KEY", "test-value")

	envMap := collectEnv()
	assert.Equal(t, "test-value", envMap["TEST_COLLECT_ENV_KEY"])
}

func TestCollectEnvHandlesEqualsInValue(t *testing.T) {
	t.Setenv("TEST_EQUALS", "key=value=extra")

	envMap := collectEnv()
	assert.Equal(t, "key=value=extra", envMap["TEST_EQUALS"])
}

func TestRegionPriorityChain(t *testing.T) {
	tests := []struct {
		name       string
		envMap     map[string]string
		wantRegion string
	}{
		{
			name: "SECRETSINIT_AWS_REGION takes priority",
			envMap: map[string]string{
				"SECRETSINIT_AWS_REGION": testRegionUSWest2,
				"AWS_REGION":            testRegionEUWest1,
				"AWS_DEFAULT_REGION":    testRegionAPSoutheast1,
			},
			wantRegion: testRegionUSWest2,
		},
		{
			name: "AWS_REGION used when SECRETSINIT_AWS_REGION absent",
			envMap: map[string]string{
				"AWS_REGION":         testRegionEUWest1,
				"AWS_DEFAULT_REGION": testRegionAPSoutheast1,
			},
			wantRegion: testRegionEUWest1,
		},
		{
			name: "AWS_DEFAULT_REGION used as last resort",
			envMap: map[string]string{
				"AWS_DEFAULT_REGION": testRegionAPSoutheast1,
			},
			wantRegion: testRegionAPSoutheast1,
		},
		{
			name:       "empty when no region set",
			envMap:     map[string]string{},
			wantRegion: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			region := resolveRegion(tc.envMap)
			assert.Equal(t, tc.wantRegion, region)
		})
	}
}

func TestStripInternalEnvVars(t *testing.T) {
	t.Parallel()

	envMap := map[string]string{
		"DB_PASSWORD":                "s3cr3t",
		"AWS_REGION":                 testRegionUSEast1,
		"SECRETSINIT_AWS_REGION":     testRegionUSEast1,
		"SECRETSINIT_IGNORE_MISSING": "true",
		"SSL_CERT_FILE":              injectedSSLCertPath,
		"APP_NAME":                   "myapp",
	}

	stripInternalEnvVars(envMap)

	// Internal vars should be removed.
	_, hasRegion := envMap["SECRETSINIT_AWS_REGION"]
	_, hasIgnore := envMap["SECRETSINIT_IGNORE_MISSING"]
	_, hasSSL := envMap["SSL_CERT_FILE"]
	assert.False(t, hasRegion, "SECRETSINIT_AWS_REGION should be stripped")
	assert.False(t, hasIgnore, "SECRETSINIT_IGNORE_MISSING should be stripped")
	assert.False(t, hasSSL, "SSL_CERT_FILE should be stripped when it matches injected path")

	// App vars should be preserved.
	assert.Equal(t, "s3cr3t", envMap["DB_PASSWORD"])
	assert.Equal(t, testRegionUSEast1, envMap["AWS_REGION"])
	assert.Equal(t, "myapp", envMap["APP_NAME"])
}

func TestStripInternalEnvVarsPreservesAppSSLCertFile(t *testing.T) {
	t.Parallel()

	customCA := "/etc/ssl/certs/custom-ca.crt"
	envMap := map[string]string{
		"DB_PASSWORD":  "s3cr3t",
		"SSL_CERT_FILE": customCA,
	}

	stripInternalEnvVars(envMap)

	// App's own SSL_CERT_FILE should NOT be stripped.
	assert.Equal(t, customCA, envMap["SSL_CERT_FILE"], "app's SSL_CERT_FILE should be preserved")
}

func TestStripInternalEnvVarsNoOp(t *testing.T) {
	t.Parallel()

	envMap := map[string]string{
		"DB_PASSWORD": "s3cr3t",
		"APP_NAME":    "myapp",
	}

	stripInternalEnvVars(envMap)

	require.Len(t, envMap, 2)
	assert.Equal(t, "s3cr3t", envMap["DB_PASSWORD"])
	assert.Equal(t, "myapp", envMap["APP_NAME"])
}

func TestAWSCredentialEnvVarsPreservedInMap(t *testing.T) {
	// Simulate what resolveSecrets does: os.Unsetenv removes from process env,
	// but the values should still be in the envMap for the app.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret123")
	t.Setenv("AWS_SESSION_TOKEN", "token456")

	envMap := collectEnv()

	// Values are in the map before unsetenv.
	assert.Equal(t, "AKIATEST", envMap["AWS_ACCESS_KEY_ID"])
	assert.Equal(t, "secret123", envMap["AWS_SECRET_ACCESS_KEY"])
	assert.Equal(t, "token456", envMap["AWS_SESSION_TOKEN"])

	// Simulate the unsetenv that resolveSecrets does.
	for _, key := range awsCredentialEnvVars {
		t.Setenv(key, "") // t.Setenv restores after test; simulate unset effect
	}

	// Map still has original values — they survive os.Unsetenv.
	assert.Equal(t, "AKIATEST", envMap["AWS_ACCESS_KEY_ID"])
	assert.Equal(t, "secret123", envMap["AWS_SECRET_ACCESS_KEY"])
	assert.Equal(t, "token456", envMap["AWS_SESSION_TOKEN"])
}
