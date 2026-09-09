package httpactionsserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"go.miloapis.com/auth-provider-zitadel/internal/emailverified"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"

	"go.miloapis.com/auth-provider-zitadel/internal/userprovision"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
)

type mockZitadelAPI struct {
	listSessionsFunc     func(ctx context.Context, userID string) ([]zitadel.Session, error)
	listUserMetadataFunc func(ctx context.Context, userID string) ([]zitadel.UserMetadata, error)
	authMethodTypesFunc  func(ctx context.Context, userID string) ([]string, error)
	registrationLinkFunc func(ctx context.Context, userID string) (string, string, error)
	getUserByIDFunc      func(ctx context.Context, userID string) (*zitadel.User, error)
}

// ListUserMetadata backs A-PR2's passkey-name lookup. Left nil it returns
// (nil, nil), which is the "key absent" degradation — one of the five paths
// that must still send the removal email, just without the name.
func (m *mockZitadelAPI) ListUserMetadata(ctx context.Context, userID string) ([]zitadel.UserMetadata, error) {
	if m.listUserMetadataFunc != nil {
		return m.listUserMetadataFunc(ctx, userID)
	}
	return nil, nil
}

func (m *mockZitadelAPI) ListSessions(ctx context.Context, userID string) ([]zitadel.Session, error) {
	if m.listSessionsFunc != nil {
		return m.listSessionsFunc(ctx, userID)
	}
	return nil, nil
}
func (m *mockZitadelAPI) GetSession(ctx context.Context, sessionID string) (*zitadel.Session, error) {
	return nil, nil
}
func (m *mockZitadelAPI) DeleteSession(ctx context.Context, userID, sessionID string) error {
	return nil
}
func (m *mockZitadelAPI) ListIDPLinks(ctx context.Context, userID string) ([]zitadel.IDPLink, error) {
	return nil, nil
}
func (m *mockZitadelAPI) ListPasskeys(ctx context.Context, userID string) ([]zitadel.Passkey, error) {
	return nil, nil
}

func (m *mockZitadelAPI) CreatePasskeyRegistrationLink(ctx context.Context, userID string) (string, string, error) {
	if m.registrationLinkFunc != nil {
		return m.registrationLinkFunc(ctx, userID)
	}
	return "code-id-1", "K7QM2XD4", nil
}

func (m *mockZitadelAPI) ListAuthMethodTypes(ctx context.Context, userID string) ([]string, error) {
	if m.authMethodTypesFunc != nil {
		return m.authMethodTypesFunc(ctx, userID)
	}
	return nil, nil
}
func (m *mockZitadelAPI) CreateOrganization(ctx context.Context, name string) (string, error) {
	return "", nil
}
func (m *mockZitadelAPI) CreateOrganizationWithID(ctx context.Context, name, customOrgID string) (string, error) {
	return "", nil
}
func (m *mockZitadelAPI) DeleteOrganization(ctx context.Context, orgID string) error { return nil }
func (m *mockZitadelAPI) GetOrganization(ctx context.Context, orgID string) (*zitadel.Organization, error) {
	return nil, nil
}
func (m *mockZitadelAPI) GetUserByID(ctx context.Context, userID string) (*zitadel.User, error) {
	if m.getUserByIDFunc != nil {
		return m.getUserByIDFunc(ctx, userID)
	}
	return nil, nil
}
func (m *mockZitadelAPI) ListHumanUsers(context.Context, uint64, uint32) ([]zitadel.User, int, error) {
	return nil, 0, nil
}
func (m *mockZitadelAPI) GetMachineUserByUsername(ctx context.Context, orgID, username string) (*zitadel.User, error) {
	return nil, nil
}
func (m *mockZitadelAPI) AddMachineUserInOrganization(ctx context.Context, orgID, userID, username, displayName string) (string, error) {
	return "", nil
}
func (m *mockZitadelAPI) DeleteUser(ctx context.Context, userID string) error            { return nil }
func (m *mockZitadelAPI) DeactivateUser(ctx context.Context, orgID, userID string) error { return nil }
func (m *mockZitadelAPI) ReactivateUser(ctx context.Context, orgID, userID string) error { return nil }
func (m *mockZitadelAPI) ListMachineAccountsInOrganization(ctx context.Context, orgID string) ([]*zitadel.User, error) {
	return nil, nil
}
func (m *mockZitadelAPI) AddMachineKeyInOrganization(ctx context.Context, orgID, userID string, publicKey []byte, expirationDate *time.Time) (string, []byte, error) {
	return "", nil, nil
}
func (m *mockZitadelAPI) ListMachineKeysInOrganization(ctx context.Context, orgID, userID string) ([]*zitadel.MachineKey, error) {
	return nil, nil
}
func (m *mockZitadelAPI) RemoveMachineKeyInOrganization(ctx context.Context, orgID, userID, keyID string) error {
	return nil
}

// logEntry captures a single structured log record emitted during a test.
type logEntry struct {
	msg string
	kv  map[string]any
}

// captureSink is a minimal logr.LogSink that records Info records so tests can
// assert on structured fields instead of scraping stdout.
type captureSink struct {
	entries *[]logEntry
}

func (s captureSink) Init(logr.RuntimeInfo) {}
func (s captureSink) Enabled(int) bool      { return true }
func (s captureSink) Info(_ int, msg string, kvs ...any) {
	kv := make(map[string]any, len(kvs)/2)
	for i := 0; i+1 < len(kvs); i += 2 {
		key, _ := kvs[i].(string)
		kv[key] = kvs[i+1]
	}
	*s.entries = append(*s.entries, logEntry{msg: msg, kv: kv})
}
func (s captureSink) Error(_ error, msg string, kvs ...any) { s.Info(0, msg, kvs...) }
func (s captureSink) WithValues(...any) logr.LogSink        { return s }
func (s captureSink) WithName(string) logr.LogSink          { return s }

// newTestScheme builds a runtime.Scheme that includes all API groups used by
// the handler under test.
func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = iamv1alpha1.AddToScheme(s)
	_ = notificationv1alpha1.AddToScheme(s)
	return s
}

// listProviderEmails lists every Email resource created against the fake
// client. Shared by handlers that notify via milo Email resources.
func listProviderEmails(t *testing.T, c client.Client) *notificationv1alpha1.EmailList {
	t.Helper()
	var list notificationv1alpha1.EmailList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatalf("list emails: %v", err)
	}
	return &list
}

// varsOf flattens an Email's Spec.Variables into a name->value map for
// assertions.
func varsOf(e notificationv1alpha1.Email) map[string]string {
	out := map[string]string{}
	for _, v := range e.Spec.Variables {
		out[v.Name] = v.Value
	}
	return out
}

// findEntry returns the first captured entry with the given message, or nil.
func findEntry(entries []logEntry, msg string) *logEntry {
	for i := range entries {
		if entries[i].msg == msg {
			return &entries[i]
		}
	}
	return nil
}

func TestSessionAddedHandler(t *testing.T) {
	tests := []struct {
		name           string
		reqPayload     sessionAddedRequest
		mockSessions   []zitadel.Session
		wantSuspicious bool
		wantDevice     string
		wantBrowser    string
	}{
		{
			name: "First login ever (no previous sessions)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:          "1.1.1.1",
						Description: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now(),
				},
			},
			wantSuspicious: false,
		},
		{
			name: "Same IP and UA (not suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:          "1.1.1.1",
						Description: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now(),
				},
				{
					ID:        "sess-prev",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now().Add(-1 * time.Hour),
				},
			},
			wantSuspicious: false,
		},
		{
			name: "Different IP (suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:          "2.2.2.2",
						Description: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "2.2.2.2",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now(),
				},
				{
					ID:        "sess-prev",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now().Add(-1 * time.Hour),
				},
			},
			wantSuspicious: true,
			wantDevice:     "Mac",
			wantBrowser:    "Chrome",
		},
		{
			name: "Different Browser (suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:          "1.1.1.1",
						Description: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) Firefox/100.0",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) Firefox/100.0",
					CreatedAt: time.Now(),
				},
				{
					ID:        "sess-prev",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now().Add(-1 * time.Hour),
				},
			},
			wantSuspicious: true,
			wantDevice:     "iPhone",
			wantBrowser:    "Firefox",
		},
		{
			name: "Mobile Firefox and oidc_session.added (suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:            "1.1.1.1",
						FingerprintID: "031d5d16-1258-4681-afb8-579fbc3871bb",
						Description:   "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) Firefox/100.0",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) Firefox/100.0",
					CreatedAt: time.Now(),
				},
				{
					ID:        "sess-prev",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now().Add(-1 * time.Hour),
				},
			},
			wantSuspicious: true,
			wantDevice:     "iPhone",
			wantBrowser:    "Firefox",
		},
		{
			name: "Different Fingerprint ID but same IP and UA (suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:            "1.1.1.1",
						FingerprintID: "new-fingerprint",
						Description:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now(),
				},
				{
					ID:            "sess-prev",
					UserID:        "user-1",
					IP:            "1.1.1.1",
					UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					FingerprintID: "old-fingerprint",
					CreatedAt:     time.Now().Add(-1 * time.Hour),
				},
			},
			wantSuspicious: true,
			wantDevice:     "Mac",
			wantBrowser:    "Chrome",
		},
		{
			// Regression: the most-recent *other* session has a rotated
			// fingerprint, but the current fingerprint reappears in an older
			// session — a returning device, so this must NOT be flagged.
			name: "Returning fingerprint seen in older session (not suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:            "1.1.1.1",
						FingerprintID: "known-fingerprint",
						Description:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:            "sess-curr",
					UserID:        "user-1",
					IP:            "1.1.1.1",
					UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					FingerprintID: "known-fingerprint",
					CreatedAt:     time.Now(),
				},
				{
					ID:            "sess-recent",
					UserID:        "user-1",
					IP:            "1.1.1.1",
					UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					FingerprintID: "rotated-fingerprint",
					CreatedAt:     time.Now().Add(-1 * time.Hour),
				},
				{
					ID:            "sess-old",
					UserID:        "user-1",
					IP:            "1.1.1.1",
					UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					FingerprintID: "known-fingerprint",
					CreatedAt:     time.Now().Add(-24 * time.Hour),
				},
			},
		},
		{
			name: "IP and UA match different past sessions in history (not suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:          "1.1.1.1",
						Description: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now(),
				},
				{
					ID:        "sess-recent",
					UserID:    "user-1",
					IP:        "2.2.2.2",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now().Add(-1 * time.Hour),
				},
				{
					ID:        "sess-old",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
					CreatedAt: time.Now().Add(-2 * time.Hour),
				},
			},
			wantSuspicious: false,
		},
		{
			name: "Passkey-authenticated session is exempt even with a new IP",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:          "9.9.9.9",
						Description: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:              "sess-curr",
					UserID:          "user-1",
					IP:              "9.9.9.9",
					UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt:       time.Now(),
					PasskeyVerified: true,
				},
				{
					ID:        "sess-prev",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
					CreatedAt: time.Now().Add(-1 * time.Hour),
				},
			},
			wantSuspicious: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockZitadelAPI{
				listSessionsFunc: func(ctx context.Context, userID string) ([]zitadel.Session, error) {
					return tt.mockSessions, nil
				},
			}

			server := &Server{
				// SuspiciousLoginEmailTemplate is intentionally empty so the
				// email path is skipped and no k8s User lookup is needed.
				config:            &ServerConfig{},
				validateSignature: func(payload []byte, header string, signingKey string) error { return nil },
				zitadelClient:     mockClient,
				k8sClient:         fake.NewClientBuilder().WithScheme(newTestScheme()).Build(),
			}

			payloadBytes, err := json.Marshal(tt.reqPayload)
			if err != nil {
				t.Fatalf("failed to marshal request payload: %v", err)
			}

			var entries []logEntry
			ctx := logf.IntoContext(context.Background(), logr.New(captureSink{entries: &entries}))
			req := httptest.NewRequest(http.MethodPost, "/v1/actions/session-added", bytes.NewReader(payloadBytes)).WithContext(ctx)
			w := httptest.NewRecorder()

			server.sessionAddedHandler(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected status OK, got %d. Body: %s", w.Code, w.Body.String())
			}

			susp := findEntry(entries, "Suspicious login detected")
			isSuspicious := susp != nil
			if isSuspicious != tt.wantSuspicious {
				t.Errorf("expected suspicious to be %v, got %v. Captured entries: %+v", tt.wantSuspicious, isSuspicious, entries)
			}

			if tt.wantSuspicious {
				if susp.kv["device"] != tt.wantDevice {
					t.Errorf("expected device %q, got %v", tt.wantDevice, susp.kv["device"])
				}
				if susp.kv["browser"] != tt.wantBrowser {
					t.Errorf("expected browser %q, got %v", tt.wantBrowser, susp.kv["browser"])
				}
			}
		})
	}
}

func TestSessionAddedHandlerErrorPaths(t *testing.T) {
	const validBody = `{"event_type":"oidc_session.added","aggregateID":"sess-curr","event_payload":{"userID":"user-1"}}`

	okSig := func(payload []byte, header, signingKey string) error { return nil }
	failSig := func(payload []byte, header, signingKey string) error { return errors.New("bad signature") }

	mock := &mockZitadelAPI{
		listSessionsFunc: func(ctx context.Context, userID string) ([]zitadel.Session, error) {
			return nil, nil
		},
	}

	tests := []struct {
		name       string
		method     string
		body       string
		sig        ValidateSignatureFunc
		client     zitadel.API
		wantStatus int
	}{
		{
			name:       "wrong method returns 405",
			method:     http.MethodGet,
			body:       validBody,
			sig:        okSig,
			client:     mock,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "signature failure returns 401",
			method:     http.MethodPost,
			body:       validBody,
			sig:        failSig,
			client:     mock,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid json returns 400",
			method:     http.MethodPost,
			body:       "{not-json",
			sig:        okSig,
			client:     mock,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unsupported event type returns 400",
			method:     http.MethodPost,
			body:       `{"event_type":"user.added","event_payload":{"userID":"user-1"}}`,
			sig:        okSig,
			client:     mock,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing userID returns 400",
			method:     http.MethodPost,
			body:       `{"event_type":"oidc_session.added"}`,
			sig:        okSig,
			client:     mock,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "nil zitadel client returns 503",
			method:     http.MethodPost,
			body:       validBody,
			sig:        okSig,
			client:     nil,
			wantStatus: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{
				config:            &ServerConfig{},
				validateSignature: tt.sig,
				zitadelClient:     tt.client,
				k8sClient:         fake.NewClientBuilder().WithScheme(newTestScheme()).Build(),
			}

			req := httptest.NewRequest(tt.method, "/v1/actions/session-added", bytes.NewReader([]byte(tt.body)))
			w := httptest.NewRecorder()

			server.sessionAddedHandler(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d. Body: %s", tt.wantStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestSendSuspiciousLoginEmail(t *testing.T) {
	const (
		userID    = "362926680773230861"
		namespace = "milo-system"
		template  = "emailtemplates.notification.miloapis.com-usersuspiciousemailtemplate"
	)

	user := &iamv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: userID},
		Spec: iamv1alpha1.UserSpec{
			GivenName:  "Jane",
			FamilyName: "Doe",
			Email:      "jane.doe@example.com",
		},
	}

	t.Run("skips when template not configured", func(t *testing.T) {
		k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
		s := &Server{
			config:    &ServerConfig{NotificationNamespace: namespace},
			k8sClient: k8s,
		}
		var entries []logEntry
		log := logr.New(captureSink{entries: &entries})
		if err := sendSuspiciousLoginEmail(context.Background(), log, s, userID, "2026-06-05T12:00:00Z", "1.2.3.4", "Mac", "Safari", "Brazil"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if findEntry(entries, "Suspicious login email template not configured; skipping notification") == nil {
			t.Error("expected skip log entry, got none")
		}
		// Confirm no Email resource was created.
		emails := &notificationv1alpha1.EmailList{}
		if err := k8s.List(context.Background(), emails); err != nil {
			t.Fatalf("list emails: %v", err)
		}
		if len(emails.Items) != 0 {
			t.Errorf("expected 0 emails, got %d", len(emails.Items))
		}
	})

	t.Run("returns error when user not found", func(t *testing.T) {
		k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
		s := &Server{
			config:    &ServerConfig{SuspiciousLoginEmailTemplate: template, NotificationNamespace: namespace},
			k8sClient: k8s,
		}
		log := logr.New(captureSink{entries: &[]logEntry{}})
		err := sendSuspiciousLoginEmail(context.Background(), log, s, "nonexistent-user", "2026-06-05T12:00:00Z", "1.2.3.4", "Mac", "Safari", "Brazil")
		if err == nil {
			t.Error("expected error for missing user, got nil")
		}
	})

	t.Run("creates Email resource with correct fields", func(t *testing.T) {
		k8s := fake.NewClientBuilder().
			WithScheme(newTestScheme()).
			WithObjects(user).
			Build()
		s := &Server{
			config:    &ServerConfig{SuspiciousLoginEmailTemplate: template, NotificationNamespace: namespace},
			k8sClient: k8s,
		}
		var entries []logEntry
		log := logr.New(captureSink{entries: &entries})

		if err := sendSuspiciousLoginEmail(context.Background(), log, s, userID, "2026-06-05T12:00:00Z", "186.158.228.76", "Mac", "Safari", "Brazil"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		emails := &notificationv1alpha1.EmailList{}
		if err := k8s.List(context.Background(), emails); err != nil {
			t.Fatalf("list emails: %v", err)
		}
		if len(emails.Items) != 1 {
			t.Fatalf("expected 1 Email resource, got %d", len(emails.Items))
		}
		e := emails.Items[0]

		if e.Namespace != namespace {
			t.Errorf("expected namespace %q, got %q", namespace, e.Namespace)
		}
		if e.Spec.TemplateRef.Name != template {
			t.Errorf("expected template %q, got %q", template, e.Spec.TemplateRef.Name)
		}
		if e.Spec.Recipient.UserRef.Name != userID {
			t.Errorf("expected userRef.name %q, got %q", userID, e.Spec.Recipient.UserRef.Name)
		}
		if e.Spec.Priority != notificationv1alpha1.EmailPriorityHigh {
			t.Errorf("expected priority high, got %q", e.Spec.Priority)
		}

		vars := make(map[string]string, len(e.Spec.Variables))
		for _, v := range e.Spec.Variables {
			vars[v.Name] = v.Value
		}
		checks := map[string]string{
			"UserName":  "Jane Doe",
			"Email":     "jane.doe@example.com",
			"IpAddress": "186.158.228.76",
			"Location":  "Brazil",
			"Browser":   "Safari",
			"Device":    "Mac",
		}
		for k, want := range checks {
			if got := vars[k]; got != want {
				t.Errorf("variable %q: expected %q, got %q", k, want, got)
			}
		}
		if vars["SignInTime"] == "" {
			t.Error("expected non-empty SignInTime variable")
		}
		if findEntry(entries, "Suspicious login notification email created") == nil {
			t.Error("expected success log entry, got none")
		}
	})
}

func TestCreateUserAccountHandler(t *testing.T) {
	const eventPayloadBody = `{
		"aggregateID": "362926680773230861",
		"aggregateType": "user",
		"resourceOwner": "org-1",
		"instanceID": "inst-1",
		"version": "v2",
		"sequence": 1,
		"event_type": "user.human.added",
		"created_at": "2026-06-05T12:00:00Z",
		"userID": "362926680773230861",
		"event_payload": {
			"userName": "jane",
			"firstName": "Jane",
			"lastName": "Doe",
			"displayName": "Jane Doe",
			"email": "jane@example.com"
		}
	}`

	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
		seed       []client.Object
	}{
		{
			name:       "creates user returns 201",
			method:     http.MethodPost,
			body:       eventPayloadBody,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "duplicate user returns 200",
			method:     http.MethodPost,
			body:       eventPayloadBody,
			wantStatus: http.StatusOK,
			seed: []client.Object{
				userprovision.NewUser("362926680773230861", "jane@example.com", "Jane", "Doe"),
			},
		},
		{
			name:       "method not allowed",
			method:     http.MethodGet,
			body:       "",
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "unsupported event type",
			method:     http.MethodPost,
			body:       `{"event_type":"user.machine.added"}`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8s := fake.NewClientBuilder().
				WithScheme(newTestScheme()).
				WithObjects(tt.seed...).
				Build()
			s := &Server{
				config:            NewServerConfig(),
				k8sClient:         k8s,
				validateSignature: func([]byte, string, string) error { return nil },
			}

			req := httptest.NewRequest(tt.method, "/v1/actions/create-user-account", bytes.NewBufferString(tt.body))
			rr := httptest.NewRecorder()
			s.createUserAccountHandler(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d (body: %s)", tt.wantStatus, rr.Code, rr.Body.String())
			}

			if tt.wantStatus == http.StatusCreated || tt.wantStatus == http.StatusOK {
				got := &iamv1alpha1.User{}
				if err := k8s.Get(context.Background(), client.ObjectKey{Name: "362926680773230861"}, got); err != nil {
					t.Fatalf("expected User resource to exist: %v", err)
				}
				if got.Spec.Email != "jane@example.com" {
					t.Errorf("expected email %q, got %q", "jane@example.com", got.Spec.Email)
				}
			}
		})
	}
}

func TestParseDeviceAndBrowser(t *testing.T) {
	tests := []struct {
		ua          string
		wantDevice  string
		wantBrowser string
	}{
		{
			ua:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantDevice:  "Windows PC",
			wantBrowser: "Chrome",
		},
		{
			ua:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			wantDevice:  "Mac",
			wantBrowser: "Safari",
		},
		{
			ua:          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			wantDevice:  "iPhone",
			wantBrowser: "Safari",
		},
		{
			ua:          "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			wantDevice:  "Android Device",
			wantBrowser: "Chrome",
		},
		{
			ua:          "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
			wantDevice:  "Linux PC",
			wantBrowser: "Firefox",
		},
		{
			ua:          "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/120.0 Mobile/15E148 Safari/605.1.15",
			wantDevice:  "iPad",
			wantBrowser: "Firefox",
		},
		{
			ua:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			wantDevice:  "Mac",
			wantBrowser: "Edge",
		},
		{
			ua:          "Unknown user agent",
			wantDevice:  "Unknown Device",
			wantBrowser: "Unknown Browser",
		},
		{
			ua:          "Safari, 26.3.1, ,  Apple, Macintosh, , WebKit, 605.1.15, , Mac OS, 10.15.7, ",
			wantDevice:  "Mac",
			wantBrowser: "Safari",
		},
		{
			ua:          "Chrome, 148.0.7778.166, , mobile, Apple, iPhone, , WebKit, 605.1.15, , iOS, 26.1.0, ",
			wantDevice:  "iPhone",
			wantBrowser: "Chrome",
		},
	}

	for _, tt := range tests {
		gotDevice := parseDevice(tt.ua)
		gotBrowser := parseBrowser(tt.ua)
		if gotDevice != tt.wantDevice {
			t.Errorf("parseDevice(%q) = %q, want %q", tt.ua, gotDevice, tt.wantDevice)
		}
		if gotBrowser != tt.wantBrowser {
			t.Errorf("parseBrowser(%q) = %q, want %q", tt.ua, gotBrowser, tt.wantBrowser)
		}
	}
}

func TestParseIDPUserData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		raw      string
		provider iamv1alpha1.AuthProvider
		avatar   string
		wantErr  bool
	}{
		{
			name:     "google nested picture",
			raw:      `{"User":{"picture":"https://lh3.googleusercontent.com/a/example"}}`,
			provider: iamv1alpha1.AuthProviderGoogle,
			avatar:   "https://lh3.googleusercontent.com/a/example",
		},
		{
			name:     "github nested avatar_url",
			raw:      `{"User":{"avatar_url":"https://avatars.githubusercontent.com/u/1"}}`,
			provider: iamv1alpha1.AuthProviderGitHub,
			avatar:   "https://avatars.githubusercontent.com/u/1",
		},
		{
			name:     "github top-level avatar_url",
			raw:      `{"avatar_url":"https://avatars.githubusercontent.com/u/2"}`,
			provider: iamv1alpha1.AuthProviderGitHub,
			avatar:   "https://avatars.githubusercontent.com/u/2",
		},
		{
			name:    "unknown provider",
			raw:     `{"email":"nobody@example.com"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			provider, avatar, err := parseIDPUserData([]byte(tt.raw))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if provider != tt.provider {
				t.Fatalf("provider = %q, want %q", provider, tt.provider)
			}
			if avatar != tt.avatar {
				t.Fatalf("avatar = %q, want %q", avatar, tt.avatar)
			}
		})
	}
}

func TestMiloUserIDFromIdpIntent(t *testing.T) {
	t.Parallel()

	req := IdpIntentSucceededRequest{}
	req.EventPayload.UserID = "payload-id"
	if got := miloUserIDFromIdpIntent(req); got != "payload-id" {
		t.Fatalf("got %q, want payload-id", got)
	}

	req = IdpIntentSucceededRequest{UserID: "top-level-id"}
	if got := miloUserIDFromIdpIntent(req); got != "top-level-id" {
		t.Fatalf("got %q, want top-level-id", got)
	}
}

// C11: the field must be right from the first reconcile, so provisioning reads
// Zitadel's verified flag once and records it. IdP-created users are verified at
// creation and get Verified immediately; email signups get Unverified.
func TestCreateUserAccountHandler_SetsInitialEmailVerified(t *testing.T) {
	const body = `{
		"aggregateID": "362926680773230861",
		"event_type": "user.human.added",
		"created_at": "2026-06-05T12:00:00Z",
		"userID": "362926680773230861",
		"event_payload": {"firstName":"Jane","lastName":"Doe","email":"jane@example.com"}
	}`

	for name, verified := range map[string]bool{
		"IdP-created user is verified at creation": true,
		"email signup is not yet verified":         false,
	} {
		t.Run(name, func(t *testing.T) {
			k8s := fake.NewClientBuilder().
				WithScheme(newTestScheme()).
				WithStatusSubresource(&iamv1alpha1.User{}).
				Build()
			s := &Server{
				config:            NewServerConfig(),
				k8sClient:         k8s,
				validateSignature: func([]byte, string, string) error { return nil },
				zitadelClient: &mockZitadelAPI{
					getUserByIDFunc: func(_ context.Context, id string) (*zitadel.User, error) {
						return &zitadel.User{ID: id, Email: "jane@example.com", IsEmailVerified: verified}, nil
					},
				},
			}

			req := httptest.NewRequest(http.MethodPost, "/v1/actions/create-user-account", bytes.NewBufferString(body))
			rr := httptest.NewRecorder()
			s.createUserAccountHandler(rr, req)

			if rr.Code != http.StatusCreated {
				t.Fatalf("expected 201, got %d (%s)", rr.Code, rr.Body.String())
			}
			got := &iamv1alpha1.User{}
			if err := k8s.Get(context.Background(), client.ObjectKey{Name: "362926680773230861"}, got); err != nil {
				t.Fatalf("get user: %v", err)
			}
			if emailverified.IsVerified(got) != verified {
				t.Errorf("emailVerification verified = %v, want %v", emailverified.IsVerified(got), verified)
			}
		})
	}
}

// Best effort: a Zitadel hiccup must never fail the provisioning ack, because
// Zitadel would retry the whole create. The sweeper reconciles it instead.
func TestCreateUserAccountHandler_EmailVerifiedFailureDoesNotFailProvisioning(t *testing.T) {
	const body = `{
		"aggregateID": "362926680773230861",
		"event_type": "user.human.added",
		"created_at": "2026-06-05T12:00:00Z",
		"userID": "362926680773230861",
		"event_payload": {"firstName":"Jane","lastName":"Doe","email":"jane@example.com"}
	}`

	k8s := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithStatusSubresource(&iamv1alpha1.User{}).
		Build()
	s := &Server{
		config:            NewServerConfig(),
		k8sClient:         k8s,
		validateSignature: func([]byte, string, string) error { return nil },
		zitadelClient: &mockZitadelAPI{
			getUserByIDFunc: func(context.Context, string) (*zitadel.User, error) {
				return nil, errors.New("zitadel unreachable")
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/actions/create-user-account", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	s.createUserAccountHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 despite the Zitadel error, got %d (%s)", rr.Code, rr.Body.String())
	}
}

// A nil client is the startup window before the background initializer installs one.
func TestCreateUserAccountHandler_NoZitadelClientStillProvisions(t *testing.T) {
	const body = `{
		"aggregateID": "362926680773230861",
		"event_type": "user.human.added",
		"created_at": "2026-06-05T12:00:00Z",
		"userID": "362926680773230861",
		"event_payload": {"firstName":"Jane","lastName":"Doe","email":"jane@example.com"}
	}`

	k8s := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithStatusSubresource(&iamv1alpha1.User{}).
		Build()
	s := &Server{
		config:            NewServerConfig(),
		k8sClient:         k8s,
		validateSignature: func([]byte, string, string) error { return nil },
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/actions/create-user-account", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	s.createUserAccountHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", rr.Code, rr.Body.String())
	}
}
