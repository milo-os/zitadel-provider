package webhook

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.miloapis.com/auth-provider-zitadel/internal/emailverified"
	"go.miloapis.com/auth-provider-zitadel/internal/recoverymail"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const recoveryBody = `{"userId":"user-1","codeId":"code-id-1","code":"K7QM2XD4","returnTo":"https://auth.example.test/recover/complete","requestedBy":"self"}`

func recoveryConfig() AccountRecoveryConfig {
	return AccountRecoveryConfig{
		TemplateName:          "recovery-tpl",
		SupportTemplateName:   "recovery-support-tpl",
		NotificationNamespace: "default",
		AllowedOrigins:        []string{"https://auth.example.test"},
		ExpiryMinutes:         60,
		UserLookupAttempts:    5,
		UserLookupBaseWait:    200 * time.Millisecond,
	}
}

// verifiedUser is the only kind of user recovery mail may reach.
func verifiedUser() *iamv1alpha1.User {
	u := testUser()
	u.Status.EmailVerification = emailverified.Desired(true)
	return u
}

func unverifiedUser() *iamv1alpha1.User {
	u := testUser()
	u.Status.EmailVerification = emailverified.Desired(false)
	return u
}

func newRecoveryHandler(t *testing.T, objs ...client.Object) (*AccountRecoveryHandler, client.Client) {
	t.Helper()
	return newRecoveryHandlerWith(t, recoveryConfig(), interceptor.Funcs{}, objs...)
}

func newRecoveryHandlerWith(
	t *testing.T,
	cfg AccountRecoveryConfig,
	funcs interceptor.Funcs,
	objs ...client.Object,
) (*AccountRecoveryHandler, client.Client) {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		WithInterceptorFuncs(funcs).
		Build()
	return NewAccountRecoveryHandler(c, cfg), c
}

func postRecovery(t *testing.T, h *AccountRecoveryHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, AccountRecoveryEndpoint, bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The recipient must come from milo, never from the request.
func TestAccountRecovery_RecipientComesFromMilo(t *testing.T) {
	h, c := newRecoveryHandler(t, verifiedUser())

	rec := postRecovery(t, h, recoveryBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	list := emails(t, c)
	if len(list) != 1 {
		t.Fatalf("expected one Email, got %d", len(list))
	}
	if got := list[0].Spec.Recipient.EmailAddress; got != "person@example.test" {
		t.Errorf("recipient = %q, want the User's address", got)
	}
}

func TestAccountRecovery_BuildsAllTemplateVariables(t *testing.T) {
	h, c := newRecoveryHandler(t, verifiedUser())

	postRecovery(t, h, recoveryBody)

	vars := varsOf(emails(t, c)[0])
	if vars["UserName"] != "Ada Lovelace" {
		t.Errorf("UserName = %q", vars["UserName"])
	}
	if vars["Code"] != "K7QM2XD4" {
		t.Errorf("Code = %q", vars["Code"])
	}
	if vars["ExpiryMinutes"] != "60" {
		t.Errorf("ExpiryMinutes = %q", vars["ExpiryMinutes"])
	}

	// ActionUrl is the validated returnTo carrying all three ceremony values.
	u, err := url.Parse(vars["ActionUrl"])
	if err != nil {
		t.Fatalf("ActionUrl unparseable: %v", err)
	}
	q := u.Query()
	for k, want := range map[string]string{"userId": "user-1", "codeId": "code-id-1", "code": "K7QM2XD4"} {
		if q.Get(k) != want {
			t.Errorf("ActionUrl %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if u.Host != "auth.example.test" || u.Path != "/recover/complete" {
		t.Errorf("ActionUrl destination = %q", u.String())
	}
}

// requestedBy selects the template. A request can pick between two operator-configured
// names and nothing else — it can never name a template.
func TestAccountRecovery_RequestedBySelectsTemplate(t *testing.T) {
	tests := map[string]struct {
		requestedBy  string
		wantTemplate string
	}{
		"self":    {recoverymail.RequestedBySelf, "recovery-tpl"},
		"support": {recoverymail.RequestedBySupport, "recovery-support-tpl"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h, c := newRecoveryHandler(t, verifiedUser())

			body := `{"userId":"user-1","codeId":"code-id-1","code":"K7QM2XD4",` +
				`"returnTo":"https://auth.example.test/recover/complete","requestedBy":"` + tt.requestedBy + `"}`
			if rec := postRecovery(t, h, body); rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
			}

			e := emails(t, c)[0]
			if e.Spec.TemplateRef.Name != tt.wantTemplate {
				t.Errorf("templateRef = %q, want %q", e.Spec.TemplateRef.Name, tt.wantTemplate)
			}
			if got := e.Labels[recoverymail.LabelRequestedBy]; got != tt.requestedBy {
				t.Errorf("requested-by label = %q, want %q", got, tt.requestedBy)
			}
		})
	}
}

func TestAccountRecovery_RejectsUnknownRequestedBy(t *testing.T) {
	h, c := newRecoveryHandler(t, verifiedUser())

	for _, requestedBy := range []string{"admin", "SELF", "", "self "} {
		body := `{"userId":"user-1","codeId":"code-id-1","code":"K7QM2XD4",` +
			`"returnTo":"https://auth.example.test/recover/complete","requestedBy":"` + requestedBy + `"}`
		if rec := postRecovery(t, h, body); rec.Code != http.StatusBadRequest {
			t.Errorf("requestedBy=%q: expected 400, got %d", requestedBy, rec.Code)
		}
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("expected no Email, got %d", n)
	}
}

// The whole point of the check: nothing is mailed to an address nobody proved.
func TestAccountRecovery_UnverifiedUserIs422AndSendsNothing(t *testing.T) {
	for name, u := range map[string]*iamv1alpha1.User{
		"Unverified":     unverifiedUser(),
		"not yet synced": testUser(),
	} {
		t.Run(name, func(t *testing.T) {
			h, c := newRecoveryHandler(t, u)

			rec := postRecovery(t, h, recoveryBody)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("expected 422, got %d", rec.Code)
			}
			if n := len(emails(t, c)); n != 0 {
				t.Fatalf("expected no Email, got %d", n)
			}
		})
	}
}

func TestAccountRecovery_RejectsUnallowlistedReturnTo(t *testing.T) {
	h, c := newRecoveryHandler(t, verifiedUser())

	body := `{"userId":"user-1","codeId":"code-id-1","code":"K7QM2XD4",` +
		`"returnTo":"https://evil.example/steal","requestedBy":"self"}`
	if rec := postRecovery(t, h, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("no Email may be created for a rejected origin, got %d", n)
	}
}

// Prefix matching must not admit "https://auth.example.test.evil.com".
func TestAccountRecovery_AllowlistMatchesOriginNotPrefix(t *testing.T) {
	h, c := newRecoveryHandler(t, verifiedUser())

	body := `{"userId":"user-1","codeId":"code-id-1","code":"K7QM2XD4",` +
		`"returnTo":"https://auth.example.test.evil.com/x","requestedBy":"self"}`
	if rec := postRecovery(t, h, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for lookalike host, got %d", rec.Code)
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("expected no Email, got %d", n)
	}
}

func TestAccountRecovery_UnknownUserIs404AndSendsNothing(t *testing.T) {
	h, c := newRecoveryHandler(t)

	body := `{"userId":"nobody","codeId":"code-id-1","code":"K7QM2XD4",` +
		`"returnTo":"https://auth.example.test/recover/complete","requestedBy":"self"}`
	if rec := postRecovery(t, h, body); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("expected no Email, got %d", n)
	}
}

func TestAccountRecovery_MissingFieldsRejected(t *testing.T) {
	h, _ := newRecoveryHandler(t, verifiedUser())

	for name, body := range map[string]string{
		"no userId":   `{"codeId":"c","code":"K","returnTo":"https://auth.example.test/x","requestedBy":"self"}`,
		"no codeId":   `{"userId":"user-1","code":"K","returnTo":"https://auth.example.test/x","requestedBy":"self"}`,
		"no code":     `{"userId":"user-1","codeId":"c","returnTo":"https://auth.example.test/x","requestedBy":"self"}`,
		"no returnTo": `{"userId":"user-1","codeId":"c","code":"K","requestedBy":"self"}`,
		"malformed":   `{`,
	} {
		t.Run(name, func(t *testing.T) {
			if rec := postRecovery(t, h, body); rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", rec.Code)
			}
		})
	}
}

func TestAccountRecovery_MethodNotAllowedAdvertisesPost(t *testing.T) {
	h, _ := newRecoveryHandler(t, verifiedUser())
	req := httptest.NewRequest(http.MethodGet, AccountRecoveryEndpoint, nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodPost {
		t.Errorf("Allow header = %q, want %q", got, http.MethodPost)
	}
}

// The User is provisioned from the same Zitadel event, so it can arrive late.
func TestAccountRecovery_UserAppearingLateIsRetried(t *testing.T) {
	var gets int
	cfg := recoveryConfig()
	cfg.UserLookupBaseWait = time.Millisecond

	h, _ := newRecoveryHandlerWith(t, cfg, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			gets++
			if gets < 3 {
				return apierrors.NewNotFound(
					schema.GroupResource{Group: iamv1alpha1.SchemeGroupVersion.Group, Resource: "users"}, key.Name)
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	}, verifiedUser())

	if rec := postRecovery(t, h, recoveryBody); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 once the User appears, got %d", rec.Code)
	}
	if gets != 3 {
		t.Errorf("Get calls = %d, want 3", gets)
	}
}

func TestAccountRecovery_CodeNeverLandsInObjectName(t *testing.T) {
	h, c := newRecoveryHandler(t, verifiedUser())

	postRecovery(t, h, recoveryBody)

	e := emails(t, c)[0]
	if strings.Contains(e.Name, "K7QM2XD4") {
		t.Fatalf("Email name %q contains the recovery code", e.Name)
	}
	if varsOf(e)["Code"] != "K7QM2XD4" {
		t.Fatal("the code must still reach the template through Variables")
	}
}

// auth-ui retries on timeout; without a deterministic name each retry sends another mail.
func TestAccountRecovery_DuplicatePostSendsOneMail(t *testing.T) {
	h, c := newRecoveryHandler(t, verifiedUser())

	for i := range 2 {
		if rec := postRecovery(t, h, recoveryBody); rec.Code != http.StatusOK {
			t.Fatalf("post %d: expected 200, got %d", i, rec.Code)
		}
	}

	if n := len(emails(t, c)); n != 1 {
		t.Fatalf("a repeated POST must not send a second mail, got %d Emails", n)
	}
}

// An apiserver rejection can quote the object it rejected, and that object carries
// the code. Neither the response nor the log may become a channel for it.
func TestAccountRecovery_CreateFailureDoesNotEchoCode(t *testing.T) {
	h, _ := newRecoveryHandlerWith(t, recoveryConfig(), interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			return errors.New(`admission denied for Email with Variables [{Code K7QM2XD4}]`)
		},
	}, verifiedUser())

	rec := postRecovery(t, h, recoveryBody)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "K7QM2XD4") {
		t.Fatalf("response echoed the recovery code: %q", rec.Body.String())
	}
}

func TestAccountRecovery_UnsetExpiryFallsBack(t *testing.T) {
	cfg := recoveryConfig()
	cfg.ExpiryMinutes = 0
	h, c := newRecoveryHandlerWith(t, cfg, interceptor.Funcs{}, verifiedUser())

	postRecovery(t, h, recoveryBody)

	if got := varsOf(emails(t, c)[0])["ExpiryMinutes"]; got != "60" {
		t.Fatalf("ExpiryMinutes = %q, want the 60-minute fallback", got)
	}
}
