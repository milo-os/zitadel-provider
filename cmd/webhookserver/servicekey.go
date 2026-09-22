package webhookserver

import (
	"encoding/json"
	"fmt"
	"os"
)

// Zitadel key file types. Only a service account key carries the userId that the
// SDK's JWT-profile assertion needs; an application key carries clientId/appId.
const (
	serviceAccountKeyType = "serviceaccount"
	applicationKeyType    = "application"
)

// zitadelKey is the identifying part of a Zitadel key file; the PEM is not decoded.
type zitadelKey struct {
	Type     string `json:"type"`
	UserID   string `json:"userId"`
	ClientID string `json:"clientId"`
	AppID    string `json:"appId"`
	KeyID    string `json:"keyId"`
}

// validateServiceAccountKey confirms path holds a Zitadel service account key. Zitadel
// answers an application key with an opaque "Errors.Internal", so it is caught here.
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
