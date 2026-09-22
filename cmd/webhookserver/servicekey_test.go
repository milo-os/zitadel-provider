package webhookserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every fixture below is synthetic. The ids are obviously fake and the "key" field
// is a placeholder rather than a PEM: validateServiceAccountKey judges the SHAPE of
// the JSON, so no real key material is needed to exercise it — and none belongs in
// a repository.
const (
	fixtureServiceAccountKey = `{
  "type": "serviceaccount",
  "keyId": "000000000000000001",
  "key": "-----BEGIN RSA PRIVATE KEY-----\nNOT-A-REAL-KEY\n-----END RSA PRIVATE KEY-----\n",
  "userId": "000000000000000002"
}`
	// The shape the webhook was actually mounted during the incident: an application
	// key, which carries clientId/appId and no userId.
	fixtureApplicationKey = `{
  "type": "application",
  "keyId": "000000000000000003",
  "key": "-----BEGIN RSA PRIVATE KEY-----\nNOT-A-REAL-KEY\n-----END RSA PRIVATE KEY-----\n",
  "appId": "000000000000000004",
  "clientId": "000000000000000005"
}`
)

// writeKey drops one fixture into a temp dir and returns its path.
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
		// wantErrContains is checked against the error text. Empty means the key
		// must be accepted.
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
			// Whatever went wrong, the operator has to be told which flag to fix.
			if !strings.Contains(err.Error(), "--zitadel-service-account-key") {
				t.Fatalf("error should name the flag to fix, got: %v", err)
			}
		})
	}
}

// A missing or unreadable file is the likeliest misconfiguration of all — a secret
// that was never mounted — so it gets its own check rather than a table row.
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

// The incident this guards against: infra mounted the introspection secret and the
// recovery client tried to use it as a service-user credential, which Zitadel
// answered with an opaque "Errors.Internal". The diagnostic has to be specific
// enough that the next person does not have to re-derive any of that, so it names
// BOTH secrets and BOTH flags.
func TestValidateServiceAccountKey_ApplicationKeyDiagnosticNamesBothSecrets(t *testing.T) {
	path := writeKey(t, "machine-account-key.json", fixtureApplicationKey)

	err := validateServiceAccountKey(path)

	if err == nil {
		t.Fatal("expected an application key to be refused")
	}
	for _, want := range []string{
		// What it got, and why that cannot work.
		"APPLICATION key",
		"userId",
		// The two secrets, so the reader can tell them apart at a glance.
		"iam-admin",
		"zitadel-machine-auth-api-key",
		// The two flags, so the reader knows which one to repoint.
		"--zitadel-service-account-key",
		"--zitadel-private-key",
		// The symptom they will have seen in the logs.
		"Errors.Internal",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("diagnostic should mention %q, got:\n%v", want, err)
		}
	}
}
