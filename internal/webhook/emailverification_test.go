package webhook

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := iamv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := notificationv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func newHandler(t *testing.T, objs ...client.Object) (*EmailVerificationHandler, client.Client) {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).Build()
	h := NewEmailVerificationHandler(c, EmailVerificationConfig{
		TemplateName:          "verify-tpl",
		NotificationNamespace: "default",
		AllowedOrigins:        []string{"https://auth.example.test", "http://localhost:3000"},
		ExpiryMinutes:         60,
		UserLookupAttempts:    5,
		UserLookupBaseWait:    200 * time.Millisecond,
	})
	return h, c
}

func testUser() *iamv1alpha1.User {
	return &iamv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "user-1"},
		Spec: iamv1alpha1.UserSpec{
			Email: "person@example.test", GivenName: "Ada", FamilyName: "Lovelace",
		},
	}
}

func post(t *testing.T, h *EmailVerificationHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/email/verification", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func emails(t *testing.T, c client.Client) []notificationv1alpha1.Email {
	t.Helper()
	var list notificationv1alpha1.EmailList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	return list.Items
}

func varsOf(e notificationv1alpha1.Email) map[string]string {
	out := map[string]string{}
	for _, v := range e.Spec.Variables {
		out[v.Name] = v.Value
	}
	return out
}

// The recipient must come from milo, never from the request. This is the property
// that bounds what a compromised auth-ui can do.
func TestEmailVerification_RecipientComesFromMilo(t *testing.T) {
	h, c := newHandler(t, testUser())

	rec := post(t, h, `{"userId":"user-1","code":"ABC123","returnTo":"https://auth.example.test/id/signup/complete"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	list := emails(t, c)
	if len(list) != 1 {
		t.Fatalf("expected one Email, got %d", len(list))
	}
	if got := list[0].Spec.Recipient.EmailAddress; got != "person@example.test" {
		t.Fatalf("recipient = %q, want the address from milo", got)
	}
	if got := list[0].Spec.TemplateRef.Name; got != "verify-tpl" {
		t.Fatalf("template = %q, want the configured one", got)
	}
}

func TestEmailVerification_BuildsAllTemplateVariables(t *testing.T) {
	h, c := newHandler(t, testUser())

	post(t, h, `{"userId":"user-1","code":"ABC123","returnTo":"https://auth.example.test/id/signup/complete"}`)

	v := varsOf(emails(t, c)[0])
	if v["UserName"] != "Ada Lovelace" {
		t.Errorf("UserName = %q", v["UserName"])
	}
	if v["Code"] != "ABC123" {
		t.Errorf("Code = %q", v["Code"])
	}
	if v["ExpiryMinutes"] != "60" {
		t.Errorf("ExpiryMinutes = %q", v["ExpiryMinutes"])
	}
	want := "https://auth.example.test/id/signup/complete?code=ABC123&userId=user-1"
	if v["ActionUrl"] != want {
		t.Errorf("ActionUrl = %q, want %q", v["ActionUrl"], want)
	}
}

// A foreign returnTo would mail a REAL code pointing at an attacker domain.
func TestEmailVerification_RejectsUnallowlistedReturnTo(t *testing.T) {
	h, c := newHandler(t, testUser())

	rec := post(t, h, `{"userId":"user-1","code":"ABC123","returnTo":"https://evil.example/steal"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("no Email may be created for a rejected origin, got %d", n)
	}
}

// Prefix matching must not admit "https://auth.example.test.evil.com".
func TestEmailVerification_AllowlistMatchesOriginNotPrefix(t *testing.T) {
	h, c := newHandler(t, testUser())

	rec := post(t, h, `{"userId":"user-1","code":"ABC123","returnTo":"https://auth.example.test.evil.com/x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for lookalike host, got %d", rec.Code)
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("expected no Email, got %d", n)
	}
}

func TestEmailVerification_UnknownUserIs404AndSendsNothing(t *testing.T) {
	h, c := newHandler(t)

	rec := post(t, h, `{"userId":"nobody","code":"ABC123","returnTo":"https://auth.example.test/id/signup/complete"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("expected no Email, got %d", n)
	}
}

func TestEmailVerification_MissingFieldsRejected(t *testing.T) {
	h, _ := newHandler(t, testUser())

	for name, body := range map[string]string{
		"no userId":   `{"code":"A","returnTo":"https://auth.example.test/x"}`,
		"no code":     `{"userId":"user-1","returnTo":"https://auth.example.test/x"}`,
		"no returnTo": `{"userId":"user-1","code":"A"}`,
		"malformed":   `{`,
	} {
		t.Run(name, func(t *testing.T) {
			if rec := post(t, h, body); rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", rec.Code)
			}
		})
	}
}

// Display name falls back to the address when the profile has no name.
func TestEmailVerification_UserNameFallsBackToEmail(t *testing.T) {
	u := testUser()
	u.Spec.GivenName, u.Spec.FamilyName = "", ""
	h, c := newHandler(t, u)

	post(t, h, `{"userId":"user-1","code":"ABC123","returnTo":"https://auth.example.test/id/signup/complete"}`)

	if got := varsOf(emails(t, c)[0])["UserName"]; got != "person@example.test" {
		t.Fatalf("UserName = %q, want the email address", got)
	}
}

func TestEmailVerification_RejectsNonPost(t *testing.T) {
	h, _ := newHandler(t, testUser())
	req := httptest.NewRequest(http.MethodGet, "/v1/email/verification", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

// newHandlerWith builds a handler over an intercepted fake client, for the paths that
// need the apiserver to misbehave on cue.
func newHandlerWith(
	t *testing.T,
	cfg EmailVerificationConfig,
	funcs interceptor.Funcs,
	objs ...client.Object,
) (*EmailVerificationHandler, client.Client) {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		WithInterceptorFuncs(funcs).
		Build()
	return NewEmailVerificationHandler(c, cfg), c
}

func baseConfig() EmailVerificationConfig {
	return EmailVerificationConfig{
		TemplateName:          "verify-tpl",
		NotificationNamespace: "default",
		AllowedOrigins:        []string{"https://auth.example.test"},
		ExpiryMinutes:         60,
		UserLookupAttempts:    5,
		UserLookupBaseWait:    200 * time.Millisecond,
	}
}

const goodBody = `{"userId":"user-1","code":"ABC123","returnTo":"https://auth.example.test/id/signup/complete"}`

// The User is provisioned by create-user-account from the same Zitadel event that
// produced this code, so it can arrive after the request does.
func TestEmailVerification_UserAppearingLateIsRetried(t *testing.T) {
	var gets int
	cfg := baseConfig()
	cfg.UserLookupBaseWait = time.Millisecond

	h, c := newHandlerWith(t, cfg, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*iamv1alpha1.User); ok {
				gets++
				if gets < 3 {
					return apierrors.NewNotFound(schema.GroupResource{Resource: "users"}, key.Name)
				}
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	}, testUser())

	if rec := post(t, h, goodBody); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 once the User appears, got %d: %s", rec.Code, rec.Body.String())
	}
	if gets != 3 {
		t.Fatalf("expected 3 Get attempts, got %d", gets)
	}
	if n := len(emails(t, c)); n != 1 {
		t.Fatalf("expected one Email, got %d", n)
	}
}

// The final attempt must not be followed by a sleep. The caller is blocked on this
// response, so that wait is pure latency on the 404 path.
//
// Asserted behaviorally rather than by stopwatch: the deadline sits above the correct
// total backoff (150ms) and below the total with a trailing sleep (300ms). A handler
// that sleeps after the last Get burns the deadline and reports 500 instead of 404.
func TestEmailVerification_NoSleepAfterFinalAttempt(t *testing.T) {
	cfg := baseConfig()
	cfg.UserLookupAttempts = 3
	cfg.UserLookupBaseWait = 50 * time.Millisecond

	h, _ := newHandlerWith(t, cfg, interceptor.Funcs{})

	ctx, cancel := context.WithTimeout(context.Background(), 225*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(http.MethodPost, "/v1/email/verification", bytes.NewBufferString(goodBody)).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 within the deadline, got %d — a trailing sleep would exhaust it", rec.Code)
	}
}

func TestEmailVerification_ContextCancellationAborts(t *testing.T) {
	cfg := baseConfig()
	cfg.UserLookupBaseWait = time.Second

	h, c := newHandlerWith(t, cfg, interceptor.Funcs{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := httptest.NewRequest(http.MethodPost, "/v1/email/verification", bytes.NewBufferString(goodBody)).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a cancelled context is not a missing user; expected 500, got %d", rec.Code)
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("expected no Email, got %d", n)
	}
}

// The code is live credential material. It may sit in Variables, which the notification
// pipeline needs — and nowhere else, least of all an object name the apiserver echoes
// into errors and audit logs.
func TestEmailVerification_CodeNeverLandsInObjectName(t *testing.T) {
	h, c := newHandler(t, testUser())

	post(t, h, goodBody)

	e := emails(t, c)[0]
	if strings.Contains(e.Name, "ABC123") {
		t.Fatalf("Email name %q contains the verification code", e.Name)
	}
	if varsOf(e)["Code"] != "ABC123" {
		t.Fatal("the code must still reach the template through Variables")
	}
}

// auth-ui retries on timeout. Without a deterministic name each retry sends another mail.
func TestEmailVerification_DuplicatePostSendsOneMail(t *testing.T) {
	h, c := newHandler(t, testUser())

	for i := range 2 {
		if rec := post(t, h, goodBody); rec.Code != http.StatusOK {
			t.Fatalf("post %d: expected 200, got %d", i, rec.Code)
		}
	}

	if n := len(emails(t, c)); n != 1 {
		t.Fatalf("a repeated POST must not send a second mail, got %d Emails", n)
	}
}

// A distinct code is a distinct mail — the dedup key must not collapse resends.
func TestEmailVerification_DifferentCodeSendsAnotherMail(t *testing.T) {
	h, c := newHandler(t, testUser())

	post(t, h, goodBody)
	post(t, h, `{"userId":"user-1","code":"ZZZ999","returnTo":"https://auth.example.test/id/signup/complete"}`)

	if n := len(emails(t, c)); n != 2 {
		t.Fatalf("expected two Emails for two codes, got %d", n)
	}
}

// An apiserver rejection can quote the object it rejected, and that object carries the
// code. The response must not become a channel for it.
func TestEmailVerification_CreateFailureDoesNotEchoCode(t *testing.T) {
	h, _ := newHandlerWith(t, baseConfig(), interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			return apierrors.NewBadRequest(`admission denied for Email with Variables [{Code ABC123}]`)
		},
	}, testUser())

	rec, logged := postCapturingLog(t, h, goodBody)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "ABC123") {
		t.Fatalf("response echoed the verification code: %q", rec.Body.String())
	}
	if strings.Contains(logged, "ABC123") {
		t.Fatalf("log echoed the verification code: %q", logged)
	}
}

// The dangerous case the type check exists for: a StatusError carrying no Reason. It
// still quotes the rejected object, so emptiness of Reason must not route it to the
// raw-error branch.
func TestEmailVerification_ReasonlessStatusErrorIsStillRedacted(t *testing.T) {
	h, _ := newHandlerWith(t, baseConfig(), interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			return &apierrors.StatusError{ErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Code:    http.StatusInternalServerError,
				Message: `Internal error occurred: Email with Variables [{Code ABC123}]`,
			}}
		},
	}, testUser())

	rec, logged := postCapturingLog(t, h, goodBody)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	if strings.Contains(logged, "ABC123") {
		t.Fatalf("log echoed the code from a reason-less StatusError: %q", logged)
	}
	if !strings.Contains(logged, "code 500") {
		t.Fatalf("log dropped the status code, leaving nothing to diagnose: %q", logged)
	}
}

// A transport failure never reached admission, so it cannot quote the request — and it
// is the only thing that explains a timeout. Logging it as an empty "rejection" is how
// a 15s staging failure became undiagnosable.
func TestEmailVerification_TransportErrorIsLoggedInFull(t *testing.T) {
	transport := &url.Error{
		Op:  "Post",
		URL: "https://milo.example.test/apis/notification.miloapis.com/v1alpha1/namespaces/default/emails",
		Err: context.DeadlineExceeded,
	}
	h, _ := newHandlerWith(t, baseConfig(), interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			return transport
		},
	}, testUser())

	rec, logged := postCapturingLog(t, h, goodBody)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	if !strings.Contains(logged, "context deadline exceeded") {
		t.Fatalf("transport cause was dropped from the log: %q", logged)
	}
	if strings.Contains(logged, "apiserver rejected") {
		t.Fatalf("transport failure was mislabelled as an apiserver rejection: %q", logged)
	}
}

// Rendering "expires in 0 minutes" is worse than a stale number.
func TestEmailVerification_UnsetExpiryFallsBack(t *testing.T) {
	cfg := baseConfig()
	cfg.ExpiryMinutes = 0

	h, c := newHandlerWith(t, cfg, interceptor.Funcs{}, testUser())
	post(t, h, goodBody)

	if got := varsOf(emails(t, c)[0])["ExpiryMinutes"]; got != "60" {
		t.Fatalf("ExpiryMinutes = %q, want the fallback", got)
	}
}

// url.Parse lowercases the scheme but not the host, so a capitalised allowlist entry
// would otherwise match nothing and take signup down.
func TestEmailVerification_AllowlistHostIsCaseInsensitive(t *testing.T) {
	cfg := baseConfig()
	cfg.AllowedOrigins = []string{"https://Auth.Example.Test"}

	h, _ := newHandlerWith(t, cfg, interceptor.Funcs{}, testUser())

	if rec := post(t, h, goodBody); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a case-differing host, got %d", rec.Code)
	}
}

func TestEmailVerification_MethodNotAllowedAdvertisesPost(t *testing.T) {
	h, _ := newHandler(t, testUser())
	req := httptest.NewRequest(http.MethodGet, "/v1/email/verification", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("Allow = %q, want POST", got)
	}
}

// capturingSink records what the handler logged. The response body is not the only
// place a verification code can escape, so redaction needs asserting on both.
type capturingSink struct {
	mu   sync.Mutex
	errs []string
}

func (s *capturingSink) Init(logr.RuntimeInfo)    {}
func (s *capturingSink) Enabled(int) bool         { return true }
func (s *capturingSink) Info(int, string, ...any) {}

func (s *capturingSink) Error(err error, msg string, kv ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errs = append(s.errs, fmt.Sprintf("%v | %s | %v", err, msg, kv))
}

func (s *capturingSink) WithValues(...any) logr.LogSink { return s }
func (s *capturingSink) WithName(string) logr.LogSink   { return s }

func (s *capturingSink) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.errs, "\n")
}

// postCapturingLog is post() with a logger threaded through the request context, which
// is where the handler reads it from.
func postCapturingLog(t *testing.T, h *EmailVerificationHandler, body string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	sink := &capturingSink{}
	ctx := logf.IntoContext(context.Background(), logr.New(sink))
	req := httptest.NewRequest(http.MethodPost, EmailVerificationEndpoint, bytes.NewBufferString(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, sink.text()
}
