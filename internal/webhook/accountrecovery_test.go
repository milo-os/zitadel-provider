package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// The request carries no code: the handler mints one. A body naming a codeId or a
// code is a caller from before this contract, and is rejected rather than honoured.
const recoveryBody = `{"userId":"user-1","returnTo":"https://auth.example.test/recover/complete","requestedBy":"self"}`

// mintedCode is what fakeMinter hands back; tests assert it reaches the Email and
// nothing else.
const mintedCode = "K7QM2XD4"

// fakeMinter stands in for Zitadel. It returns a fresh codeID per call, as Zitadel
// does, so no test can quietly depend on two requests colliding on one Email name.
type fakeMinter struct {
	code  string
	err   error
	calls []string
	n     int
}

func newFakeMinter() *fakeMinter { return &fakeMinter{code: mintedCode} }

func (f *fakeMinter) CreatePasskeyRegistrationLink(_ context.Context, userID string) (string, string, error) {
	f.calls = append(f.calls, userID)
	if f.err != nil {
		return "", "", f.err
	}
	f.n++
	return fmt.Sprintf("code-id-%d", f.n), f.code, nil
}

func recoveryConfig() AccountRecoveryConfig {
	return AccountRecoveryConfig{
		TemplateName:          "recovery-tpl",
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
	h, c, _ := newRecoveryHandlerWith(t, recoveryConfig(), interceptor.Funcs{}, objs...)
	return h, c
}

func newRecoveryHandlerWith(
	t *testing.T,
	cfg AccountRecoveryConfig,
	funcs interceptor.Funcs,
	objs ...client.Object,
) (*AccountRecoveryHandler, client.Client, *fakeMinter) {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		WithInterceptorFuncs(funcs).
		Build()
	minter := newFakeMinter()
	return NewAccountRecoveryHandler(c, minter, cfg), c, minter
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
	if vars["Code"] != mintedCode {
		t.Errorf("Code = %q, want the minted code", vars["Code"])
	}
	if vars["ExpiryMinutes"] != "60" {
		t.Errorf("ExpiryMinutes = %q", vars["ExpiryMinutes"])
	}

	// ActionUrl is the validated returnTo carrying the ceremony values.
	u, err := url.Parse(vars["ActionUrl"])
	if err != nil {
		t.Fatalf("ActionUrl unparseable: %v", err)
	}
	q := u.Query()
	for k, want := range map[string]string{"userId": "user-1", "codeId": "code-id-1"} {
		if q.Get(k) != want {
			t.Errorf("ActionUrl %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if u.Host != "auth.example.test" || u.Path != "/recover/complete" {
		t.Errorf("ActionUrl destination = %q", u.String())
	}
}

// Jose #1. "support" is the REST path's vocabulary: that trigger carries a
// SubjectAccessReview, a mandatory reason and a requester, and this endpoint has
// none of them. Accepting it here would let an unauthenticated caller mint an audit
// record asserting that Datum Support acted.
func TestAccountRecovery_SupportRequestedByIsRejected(t *testing.T) {
	h, c, minter := newRecoveryHandlerWith(t, recoveryConfig(), interceptor.Funcs{}, verifiedUser())

	body := `{"userId":"user-1","returnTo":"https://auth.example.test/recover/complete",` +
		`"requestedBy":"` + recoverymail.RequestedBySupport + `"}`
	rec := postRecovery(t, h, body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for requestedBy=support, got %d (%s)", rec.Code, rec.Body.String())
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("expected no Email, got %d", n)
	}
	if len(minter.calls) != 0 {
		t.Fatalf("a rejected requestedBy must not mint a code, got %d calls", len(minter.calls))
	}
}

func TestAccountRecovery_RejectsUnknownRequestedBy(t *testing.T) {
	h, c := newRecoveryHandler(t, verifiedUser())

	for _, requestedBy := range []string{"admin", "SELF", "", "self "} {
		body := `{"userId":"user-1","returnTo":"https://auth.example.test/recover/complete",` +
			`"requestedBy":"` + requestedBy + `"}`
		if rec := postRecovery(t, h, body); rec.Code != http.StatusBadRequest {
			t.Errorf("requestedBy=%q: expected 400, got %d", requestedBy, rec.Code)
		}
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("expected no Email, got %d", n)
	}
}

// Jose #2. A caller-supplied code was mailed with no check that it was minted for
// this user, exists, or is live — and any random string was a fresh codeId, which
// defeated the AlreadyExists dedupe and bypassed Zitadel's own minting throttle.
// The fix is not to validate the relayed value but to stop accepting one.
func TestAccountRecovery_RejectsCallerSuppliedCode(t *testing.T) {
	for name, body := range map[string]string{
		"code": `{"userId":"user-1","code":"ATTACKER","returnTo":"https://auth.example.test/x","requestedBy":"self"}`,
		"codeId": `{"userId":"user-1","codeId":"forged","returnTo":"https://auth.example.test/x",` +
			`"requestedBy":"self"}`,
		"both": `{"userId":"user-1","codeId":"forged","code":"ATTACKER",` +
			`"returnTo":"https://auth.example.test/x","requestedBy":"self"}`,
	} {
		t.Run(name, func(t *testing.T) {
			h, c, minter := newRecoveryHandlerWith(t, recoveryConfig(), interceptor.Funcs{}, verifiedUser())

			rec := postRecovery(t, h, body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d (%s)", rec.Code, rec.Body.String())
			}
			if n := len(emails(t, c)); n != 0 {
				t.Fatalf("expected no Email, got %d", n)
			}
			if len(minter.calls) != 0 {
				t.Fatalf("expected no mint, got %d calls", len(minter.calls))
			}
		})
	}
}

// The handler is the minting authority now. The caller learns the codeId — enough
// to seal a ticket and correlate the ceremony — and never the code.
func TestAccountRecovery_MintsTheCodeAndReturnsCodeID(t *testing.T) {
	h, c, minter := newRecoveryHandlerWith(t, recoveryConfig(), interceptor.Funcs{}, verifiedUser())

	rec := postRecovery(t, h, recoveryBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if len(minter.calls) != 1 || minter.calls[0] != "user-1" {
		t.Fatalf("mint calls = %v, want one for user-1", minter.calls)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var got struct {
		CodeID string `json:"codeId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, rec.Body.String())
	}
	if got.CodeID != "code-id-1" {
		t.Errorf("codeId = %q, want the minted id", got.CodeID)
	}
	if varsOf(emails(t, c)[0])["Code"] != mintedCode {
		t.Error("the minted code must reach the Email")
	}
}

// The code is a bearer credential. The caller asked for a mail to be sent, not for
// the credential itself: a compromised auth-ui must not be able to read it back.
func TestAccountRecovery_ResponseNeverCarriesTheCode(t *testing.T) {
	h, _, _ := newRecoveryHandlerWith(t, recoveryConfig(), interceptor.Funcs{}, verifiedUser())

	rec := postRecovery(t, h, recoveryBody)

	if strings.Contains(rec.Body.String(), mintedCode) {
		t.Fatalf("response carried the recovery code: %q", rec.Body.String())
	}
}

func TestAccountRecovery_MintFailureSendsNothing(t *testing.T) {
	h, c, minter := newRecoveryHandlerWith(t, recoveryConfig(), interceptor.Funcs{}, verifiedUser())
	minter.err = errors.New("zitadel refused")

	rec := postRecovery(t, h, recoveryBody)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("a failed mint must send no mail, got %d Emails", n)
	}
}

// The whole point of the check: nothing is mailed to an address nobody proved — and
// no code is minted for one either, so the check also bounds Zitadel-side churn.
func TestAccountRecovery_UnverifiedUserIs422AndSendsNothing(t *testing.T) {
	for name, u := range map[string]*iamv1alpha1.User{
		"Unverified":     unverifiedUser(),
		"not yet synced": testUser(),
	} {
		t.Run(name, func(t *testing.T) {
			h, c, minter := newRecoveryHandlerWith(t, recoveryConfig(), interceptor.Funcs{}, u)

			rec := postRecovery(t, h, recoveryBody)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("expected 422, got %d", rec.Code)
			}
			if n := len(emails(t, c)); n != 0 {
				t.Fatalf("expected no Email, got %d", n)
			}
			if len(minter.calls) != 0 {
				t.Fatalf("expected no mint, got %d calls", len(minter.calls))
			}
		})
	}
}

func TestAccountRecovery_RejectsUnallowlistedReturnTo(t *testing.T) {
	h, c, minter := newRecoveryHandlerWith(t, recoveryConfig(), interceptor.Funcs{}, verifiedUser())

	body := `{"userId":"user-1","returnTo":"https://evil.example/steal","requestedBy":"self"}`
	if rec := postRecovery(t, h, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("no Email may be created for a rejected origin, got %d", n)
	}
	if len(minter.calls) != 0 {
		t.Fatalf("expected no mint, got %d calls", len(minter.calls))
	}
}

// Prefix matching must not admit "https://auth.example.test.evil.com".
func TestAccountRecovery_AllowlistMatchesOriginNotPrefix(t *testing.T) {
	h, c := newRecoveryHandler(t, verifiedUser())

	body := `{"userId":"user-1","returnTo":"https://auth.example.test.evil.com/x","requestedBy":"self"}`
	if rec := postRecovery(t, h, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for lookalike host, got %d", rec.Code)
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("expected no Email, got %d", n)
	}
}

func TestAccountRecovery_UnknownUserIs404AndSendsNothing(t *testing.T) {
	h, c := newRecoveryHandler(t)

	body := `{"userId":"nobody","returnTo":"https://auth.example.test/recover/complete","requestedBy":"self"}`
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
		"no userId":   `{"returnTo":"https://auth.example.test/x","requestedBy":"self"}`,
		"no returnTo": `{"userId":"user-1","requestedBy":"self"}`,
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

	h, _, _ := newRecoveryHandlerWith(t, cfg, interceptor.Funcs{
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
	if strings.Contains(e.Name, mintedCode) {
		t.Fatalf("Email name %q contains the recovery code", e.Name)
	}
	if varsOf(e)["Code"] != mintedCode {
		t.Fatal("the code must still reach the template through Variables")
	}
}

// An apiserver rejection can quote the object it rejected, and that object carries
// the code. Neither the response nor the log may become a channel for it.
func TestAccountRecovery_CreateFailureDoesNotEchoCode(t *testing.T) {
	h, _, _ := newRecoveryHandlerWith(t, recoveryConfig(), interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			return errors.New(`admission denied for Email with Variables [{Code ` + mintedCode + `}]`)
		},
	}, verifiedUser())

	rec := postRecovery(t, h, recoveryBody)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), mintedCode) {
		t.Fatalf("response echoed the recovery code: %q", rec.Body.String())
	}
}

func TestAccountRecovery_UnsetExpiryFallsBack(t *testing.T) {
	cfg := recoveryConfig()
	cfg.ExpiryMinutes = 0
	h, c, _ := newRecoveryHandlerWith(t, cfg, interceptor.Funcs{}, verifiedUser())

	postRecovery(t, h, recoveryBody)

	if got := varsOf(emails(t, c)[0])["ExpiryMinutes"]; got != "60" {
		t.Fatalf("ExpiryMinutes = %q, want the 60-minute fallback", got)
	}
}
