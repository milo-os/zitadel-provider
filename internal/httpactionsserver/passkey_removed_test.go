package httpactionsserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// A-PR2. The removal notification, and the five documented paths on which the
// passkey name cannot be established. Every one of them must still SEND the
// email, just without the PasskeyName variable.

const (
	removedUserID  = "385506184100053027"
	removedTokenID = "tok-abc123"
)

func removedPayload(eventType, aggregateID string) string {
	return `{"aggregateID":"` + aggregateID + `","event_type":"` + eventType + `",` +
		`"created_at":"2026-08-10T09:15:00Z","userID":"someone-else",` +
		`"event_payload":{"webAuthNTokenId":"` + removedTokenID + `"}}`
}

func newRemovedServer(t *testing.T, api zitadel.API) (*Server, client.Client) {
	t.Helper()
	return newRemovedServerWithConfig(t, api, &ServerConfig{
		PasskeyRemovedEmailTemplate: "removed-tpl",
		NotificationNamespace:       "default",
	})
}

func newRemovedServerWithConfig(t *testing.T, api zitadel.API, cfg *ServerConfig) (*Server, client.Client) {
	t.Helper()
	user := &iamv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: removedUserID},
		Spec:       iamv1alpha1.UserSpec{Email: "wave@example.test", GivenName: "Wave", FamilyName: "Two"},
	}
	k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(user).Build()
	return &Server{
		config:            cfg,
		k8sClient:         k8s,
		zitadelClient:     api,
		validateSignature: func([]byte, string, string) error { return nil },
	}, k8s
}

func postRemoved(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/actions/passkey-removed", strings.NewReader(body))
	req.Header.Set("Zitadel-Signature", "t=1,v1=deadbeef")
	rec := httptest.NewRecorder()
	s.passkeyRemovedHandler(rec, req)
	return rec
}

// metadataAPI stubs only ListUserMetadata; every other call would nil-panic,
// which is the point — this handler must touch nothing else.
type metadataAPI struct {
	zitadel.API
	entries []zitadel.UserMetadata
	err     error
}

func (m *metadataAPI) ListUserMetadata(context.Context, string) ([]zitadel.UserMetadata, error) {
	return m.entries, m.err
}

func removedEmailVars(t *testing.T, c client.Client) map[string]string {
	t.Helper()
	list := listProviderEmails(t, c)
	if len(list.Items) != 1 {
		t.Fatalf("expected exactly one Email, got %d", len(list.Items))
	}
	return varsOf(list.Items[0])
}

func TestPasskeyRemoved_JSONMetadata_IncludesName(t *testing.T) {
	s, k8s := newRemovedServer(t, &metadataAPI{entries: []zitadel.UserMetadata{
		{Key: "passkey:" + removedTokenID + ":created", Value: `{"name":"iCloud Keychain"}`},
	}})

	if rec := postRemoved(t, s, removedPayload(EventTypePasskeyRemoved, removedUserID)); rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	vars := removedEmailVars(t, k8s)
	if vars["PasskeyName"] != "iCloud Keychain" {
		t.Errorf("PasskeyName = %q", vars["PasskeyName"])
	}
	if vars["UserName"] != "Wave Two" {
		t.Errorf("UserName = %q", vars["UserName"])
	}
	if vars["RemovedTime"] != "Aug 10, 2026 at 09:15 UTC" {
		t.Errorf("RemovedTime = %q", vars["RemovedTime"])
	}
}

// The five degradations. Each SENDS the email with PasskeyName absent — not
// empty. An empty value renders a blank label, which is the defect the design
// removed; an absent one renders the guarded branch.
func TestPasskeyRemoved_DegradationsSendEmptyName(t *testing.T) {
	for _, tc := range []struct {
		name string
		api  zitadel.API
	}{
		{"1: zitadel client not configured", nil},
		{"2: metadata RPC fails", &metadataAPI{err: errors.New("rpc down")}},
		{"3: key absent", &metadataAPI{entries: []zitadel.UserMetadata{{Key: "passkey:other:created", Value: `{"name":"x"}`}}}},
		{"4: legacy bare ISO value", &metadataAPI{entries: []zitadel.UserMetadata{{Key: "passkey:" + removedTokenID + ":created", Value: "2026-01-02T15:04:05Z"}}}},
		{"5: malformed JSON", &metadataAPI{entries: []zitadel.UserMetadata{{Key: "passkey:" + removedTokenID + ":created", Value: `{"name":`}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, k8s := newRemovedServer(t, tc.api)

			if rec := postRemoved(t, s, removedPayload(EventTypePasskeyRemoved, removedUserID)); rec.Code != http.StatusOK {
				t.Fatalf("degradation must still ack 200, got %d", rec.Code)
			}

			vars := removedEmailVars(t, k8s)
			name, present := vars["PasskeyName"]
			if !present {
				t.Fatal(`PasskeyName must ALWAYS be sent; an omitted variable renders "<no value>"`)
			}
			if name != "" {
				t.Fatalf("a degraded path must send an empty name, got %q", name)
			}
			if vars["UserName"] == "" || vars["RemovedTime"] == "" {
				t.Fatal("the email must still carry UserName and RemovedTime")
			}
		})
	}
}

// The bug passkey_added.go documents: UserID is the event creator, AggregateID
// is the subject. Using UserID produced zero notifications for every real
// enrollment.
func TestPasskeyRemoved_UsesAggregateIDNotUserID(t *testing.T) {
	s, k8s := newRemovedServer(t, &metadataAPI{})

	postRemoved(t, s, removedPayload(EventTypePasskeyRemoved, removedUserID))

	list := listProviderEmails(t, k8s)
	if len(list.Items) != 1 {
		t.Fatalf("expected one Email, got %d", len(list.Items))
	}
	// "someone-else" is the payload's userID; resolving by it would fail the
	// User lookup and send nothing.
	if got := list.Items[0].Spec.Recipient.UserRef.Name; got != removedUserID {
		t.Fatalf("recipient = %q, want the aggregateID %q", got, removedUserID)
	}
}

func TestPasskeyRemoved_WrongEventType_Ignored(t *testing.T) {
	s, k8s := newRemovedServer(t, &metadataAPI{})

	rec := postRemoved(t, s, removedPayload(EventTypePasskeyAdded, removedUserID))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if n := len(listProviderEmails(t, k8s).Items); n != 0 {
		t.Fatalf("a non-removal event must send nothing, got %d Emails", n)
	}
}

// Unconfigured means skip, matching PasskeyAddedEmailTemplate.
func TestPasskeyRemoved_TemplateUnconfigured_SendsNothing(t *testing.T) {
	s, k8s := newRemovedServer(t, &metadataAPI{})
	s.config.PasskeyRemovedEmailTemplate = ""

	if rec := postRemoved(t, s, removedPayload(EventTypePasskeyRemoved, removedUserID)); rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if n := len(listProviderEmails(t, k8s).Items); n != 0 {
		t.Fatalf("unconfigured template must send nothing, got %d", n)
	}
}

// No cluster passes --passkey-removed-email-template, so the default is not a
// convenience — it is the only thing that can ever configure this handler.
const defaultRemovedTemplate = "emailtemplates.notification.miloapis.com-userpasskeyremovedemailtemplate"

func TestPasskeyRemoved_DefaultConfigCarriesTemplate(t *testing.T) {
	if got := NewServerConfig().PasskeyRemovedEmailTemplate; got != defaultRemovedTemplate {
		t.Errorf("default PasskeyRemovedEmailTemplate = %q, want %q", got, defaultRemovedTemplate)
	}
}

// Exercise the real defaults, not a hand-built config. Every other test here
// hardcodes a template, which is how a fully green suite coexisted with a
// handler that skipped every removal event in every environment.
func TestPasskeyRemoved_DefaultConfigSendsNotification(t *testing.T) {
	s, k8s := newRemovedServerWithConfig(t, &metadataAPI{}, NewServerConfig())

	if rec := postRemoved(t, s, removedPayload(EventTypePasskeyRemoved, removedUserID)); rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	list := listProviderEmails(t, k8s)
	if len(list.Items) != 1 {
		t.Fatalf("the default config must send the removal notification, got %d Emails", len(list.Items))
	}
	if got := list.Items[0].Spec.TemplateRef.Name; got != defaultRemovedTemplate {
		t.Errorf("templateRef.name = %q, want %q", got, defaultRemovedTemplate)
	}
}

func TestPasskeyRemoved_BadSignature_Rejects401(t *testing.T) {
	s, _ := newRemovedServer(t, &metadataAPI{})
	s.validateSignature = func([]byte, string, string) error { return errors.New("bad") }

	if rec := postRemoved(t, s, removedPayload(EventTypePasskeyRemoved, removedUserID)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestPasskeyRemoved_MissingAggregateID_Rejects400(t *testing.T) {
	s, _ := newRemovedServer(t, &metadataAPI{})

	if rec := postRemoved(t, s, removedPayload(EventTypePasskeyRemoved, "")); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
