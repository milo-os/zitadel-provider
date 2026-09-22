package webhookserver

import (
	"encoding/json"
	"fmt"
	"os"
)

// Zitadel's two key types. A key file declares which one it is in its "type" field,
// and the two are NOT interchangeable:
//
//   - serviceAccountKeyType carries a userId and authenticates a service USER. It is
//     what profile.NewJWTProfileTokenSourceFromKeyFile — and therefore zitadel.NewSDK,
//     and therefore the recovery client — needs in order to mint an assertion.
//   - applicationKeyType carries clientId/appId and no userId. It identifies an
//     application, and is what the token introspector loads.
const (
	serviceAccountKeyType = "serviceaccount"
	applicationKeyType    = "application"
)

// zitadelKey is the shape half of a Zitadel key file. The PEM in "key" is
// deliberately not decoded here: this check exists to tell the two key TYPES apart
// before any credential is used, and the private key itself has no bearing on that.
type zitadelKey struct {
	Type     string `json:"type"`
	UserID   string `json:"userId"`
	ClientID string `json:"clientId"`
	AppID    string `json:"appId"`
	KeyID    string `json:"keyId"`
}

// validateServiceAccountKey confirms the file at path is a Zitadel SERVICE ACCOUNT
// key before it is handed to zitadel.NewSDK.
//
// Without this check, an application key reaches the token exchange and Zitadel
// answers HTTP 500 {"error":"server_error","error_description":"Errors.Internal"} —
// a message that names neither the key, the flag, nor the mistake. That is how a
// mail feature took the TokenReview webhook down for ~9.5 minutes on 2026-09-22:
// the webhook is mounted the introspection secret, and the recovery client was
// pointed at it on the assumption that one key served both callers.
func validateServiceAccountKey(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("--zitadel-service-account-key: cannot read %s: %w "+
			"(the flag must point at a mounted Zitadel service account key JSON)", path, err)
	}

	var key zitadelKey
	if err := json.Unmarshal(raw, &key); err != nil {
		return fmt.Errorf("--zitadel-service-account-key: cannot parse %s as JSON: %w "+
			"(expected a Zitadel service account key file, not a bare PEM)", path, err)
	}

	// The incident case, and the one worth spelling out in full: the operator mounted
	// the introspection secret here. Say so, name both secrets and both flags, and
	// quote the error Zitadel would otherwise have returned instead.
	if key.Type == applicationKeyType || (key.UserID == "" && (key.ClientID != "" || key.AppID != "")) {
		return fmt.Errorf("--zitadel-service-account-key: %s is a Zitadel APPLICATION key "+
			"(type %q, clientId %q, appId %q) and carries no userId, so it cannot mint the "+
			"service-user JWT the Zitadel API requires — the token exchange fails with an opaque "+
			"HTTP 500 \"Errors.Internal\". This flag needs the SERVICE ACCOUNT key (type %q, userId set), "+
			"which is the \"iam-admin\" secret. The application key is the \"zitadel-machine-auth-api-key\" "+
			"secret and belongs on --zitadel-private-key, which the token introspector uses. "+
			"The two are different credentials for different callers; one key cannot serve both",
			path, key.Type, key.ClientID, key.AppID, serviceAccountKeyType)
	}

	if key.Type != serviceAccountKeyType {
		return fmt.Errorf("--zitadel-service-account-key: %s declares type %q, want %q "+
			"(a Zitadel service account key; see the account-recovery runbook for which secret holds one)",
			path, key.Type, serviceAccountKeyType)
	}

	if key.UserID == "" {
		return fmt.Errorf("--zitadel-service-account-key: %s declares type %q but has no userId, "+
			"which is the subject the service-user JWT assertion is minted for; "+
			"the key file is incomplete", path, key.Type)
	}

	return nil
}
