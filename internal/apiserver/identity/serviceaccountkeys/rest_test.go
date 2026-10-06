package serviceaccountkeys

import (
	"encoding/json"
	"testing"
)

func TestBuildDatumCredentialsUsesServiceAccountClientID(t *testing.T) {
	const clientID = "349624629"
	credentialsJSON, err := buildDatumCredentials(
		[]byte(`{"key":"-----BEGIN PRIVATE KEY-----\\ntest\\n-----END PRIVATE KEY-----"}`),
		"625134962",
		clientID,
		"connector@platform.identity.miloapis.com",
		"",
	)
	if err != nil {
		t.Fatalf("build credentials: %v", err)
	}

	var credentials datumCredentials
	if err := json.Unmarshal(credentialsJSON, &credentials); err != nil {
		t.Fatalf("unmarshal credentials: %v", err)
	}
	if credentials.ClientID != clientID {
		t.Fatalf("client_id = %q, want %q", credentials.ClientID, clientID)
	}
}

func TestBuildDatumCredentialsOmitsPrivateKeyForClientManagedKey(t *testing.T) {
	credentialsJSON, err := buildDatumCredentials(nil, "625134962", "349624629", "connector@platform.identity.miloapis.com", "")
	if err != nil {
		t.Fatalf("build credentials: %v", err)
	}
	if credentialsJSON != nil {
		t.Fatalf("client-managed key returned private credentials: %q", credentialsJSON)
	}
}
