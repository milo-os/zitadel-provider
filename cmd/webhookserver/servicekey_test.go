package webhookserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixtures are synthetic: the "key" field is a placeholder, never real key material.
const (
	fixtureServiceAccountKey = `{
  "type": "serviceaccount",
  "keyId": "000000000000000001",
  "key": "-----BEGIN RSA PRIVATE KEY-----\nNOT-A-REAL-KEY\n-----END RSA PRIVATE KEY-----\n",
  "userId": "000000000000000002"
}`
	fixtureApplicationKey = `{
  "type": "application",
  "keyId": "000000000000000003",
  "key": "-----BEGIN RSA PRIVATE KEY-----\nNOT-A-REAL-KEY\n-----END RSA PRIVATE KEY-----\n",
  "appId": "000000000000000004",
  "clientId": "000000000000000005"
}`
)

func writeKey(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestValidateServiceAccountKey(t *testing.T) {
	for name, tc := range map[string]struct {
		contents string
		// Empty wantErrContains means the key must be accepted.
		wantErrContains string
	}{
		"a service account key is what this flag wants": {
			contents: fixtureServiceAccountKey,
		},
		"an application key is refused by name": {
			contents:        fixtureApplicationKey,
			wantErrContains: "APPLICATION key",
		},
		"serviceaccount type with no userId cannot mint a JWT": {
			contents:        `{"type":"serviceaccount","keyId":"000000000000000006","key":"x"}`,
			wantErrContains: "userId",
		},
		"an unrecognised type is refused rather than guessed at": {
			contents:        `{"type":"something-else","userId":"000000000000000007"}`,
			wantErrContains: `"serviceaccount"`,
		},
		"a key file that is not JSON names the parse failure": {
			contents:        "-----BEGIN RSA PRIVATE KEY-----\nNOT-JSON\n",
			wantErrContains: "parse",
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeKey(t, "key.json", tc.contents)

			err := validateServiceAccountKey(path)

			if tc.wantErrContains == "" {
				if err != nil {
					t.Fatalf("expected the key to be accepted, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error mentioning %q, got none", tc.wantErrContains)
			}
			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("error should mention %q, got: %v", tc.wantErrContains, err)
			}
			if !strings.Contains(err.Error(), "--zitadel-service-account-key") {
				t.Fatalf("error should name the flag to fix, got: %v", err)
			}
		})
	}
}

func TestValidateServiceAccountKey_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-written.json")

	err := validateServiceAccountKey(path)

	if err == nil {
		t.Fatal("expected an error: the key file does not exist")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error should name the path it tried to read, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--zitadel-service-account-key") {
		t.Fatalf("error should name the flag to fix, got: %v", err)
	}
}

func TestValidateServiceAccountKey_ApplicationKeyDiagnosticNamesBothSecrets(t *testing.T) {
	path := writeKey(t, "machine-account-key.json", fixtureApplicationKey)

	err := validateServiceAccountKey(path)

	if err == nil {
		t.Fatal("expected an application key to be refused")
	}
	for _, want := range []string{
		"APPLICATION key",
		"userId",
		"iam-admin",
		"zitadel-machine-auth-api-key",
		"--zitadel-service-account-key",
		"--zitadel-private-key",
		"Errors.Internal",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("diagnostic should mention %q, got:\n%v", want, err)
		}
	}
}
