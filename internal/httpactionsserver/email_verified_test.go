package httpactionsserver

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.miloapis.com/auth-provider-zitadel/internal/emailverified"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func emailVerifiedBody(eventType, aggregateID string) string {
	return `{"aggregateID":"` + aggregateID + `","event_type":"` + eventType + `",` +
		`"created_at":"2026-09-09T12:00:00Z","userID":"` + aggregateID + `"}`
}

func newEmailVerifiedServer(t *testing.T, objs ...client.Object) (*Server, client.Client) {
	t.Helper()
	k8s := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithStatusSubresource(&iamv1alpha1.User{}).
		WithObjects(objs...).
		Build()
	return &Server{
		config:            NewServerConfig(),
		k8sClient:         k8s,
		validateSignature: func([]byte, string, string) error { return nil },
	}, k8s
}

func emailVerifiedUser() *iamv1alpha1.User {
	return &iamv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "u1"},
		Spec:       iamv1alpha1.UserSpec{Email: "jane@example.com"},
	}
}

func postEmailVerified(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/actions/email-verified", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	s.emailVerifiedHandler(rr, req)
	return rr
}

func conditionOf(t *testing.T, c client.Client, name string) *iamv1alpha1.User {
	t.Helper()
	got := &iamv1alpha1.User{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: name}, got); err != nil {
		t.Fatalf("get user: %v", err)
	}
	return got
}

func TestEmailVerifiedHandler_VerifiedEventSetsTrue(t *testing.T) {
	s, c := newEmailVerifiedServer(t, emailVerifiedUser())

	rr := postEmailVerified(t, s, emailVerifiedBody(EventTypeEmailVerified, "u1"))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	if !emailverified.IsTrue(conditionOf(t, c, "u1")) {
		t.Error("EmailVerified condition is not True after a verified event")
	}
}

// A changed address is an unproven address until it is verified again.
func TestEmailVerifiedHandler_ChangedEventSetsFalse(t *testing.T) {
	u := emailVerifiedUser()
	u.Status.Conditions = []metav1.Condition{withNowCond(emailverified.Desired(true))}
	s, c := newEmailVerifiedServer(t, u)

	rr := postEmailVerified(t, s, emailVerifiedBody(EventTypeEmailChanged, "u1"))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	if emailverified.IsTrue(conditionOf(t, c, "u1")) {
		t.Error("EmailVerified condition is still True after an email-changed event")
	}
}

func withNowCond(c metav1.Condition) metav1.Condition {
	c.LastTransitionTime = metav1.Now()
	return c
}

func TestEmailVerifiedHandler_RejectsOtherEventTypes(t *testing.T) {
	s, c := newEmailVerifiedServer(t, emailVerifiedUser())

	for _, eventType := range []string{
		"user.human.added", "user.human.passwordless.token.verified", "",
	} {
		rr := postEmailVerified(t, s, emailVerifiedBody(eventType, "u1"))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("event %q: expected 400, got %d", eventType, rr.Code)
		}
	}
	// Nothing may be written for an event this handler is not bound to.
	if got := conditionOf(t, c, "u1"); len(got.Status.Conditions) != 0 {
		t.Errorf("conditions were written for an unsupported event: %+v", got.Status.Conditions)
	}
}

func TestEmailVerifiedHandler_BadSignatureIs401(t *testing.T) {
	s, c := newEmailVerifiedServer(t, emailVerifiedUser())
	s.validateSignature = func([]byte, string, string) error { return errors.New("bad signature") }

	rr := postEmailVerified(t, s, emailVerifiedBody(EventTypeEmailVerified, "u1"))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if emailverified.IsTrue(conditionOf(t, c, "u1")) {
		t.Error("an unsigned request wrote the condition")
	}
}

func TestEmailVerifiedHandler_MissingUserIs404(t *testing.T) {
	s, _ := newEmailVerifiedServer(t)
	s.config.IdpIntentUserLookupAttempts = 1
	s.config.IdpIntentUserLookupBaseWait = 0

	rr := postEmailVerified(t, s, emailVerifiedBody(EventTypeEmailVerified, "nobody"))

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestEmailVerifiedHandler_MissingAggregateIDIs400(t *testing.T) {
	s, _ := newEmailVerifiedServer(t, emailVerifiedUser())

	rr := postEmailVerified(t, s, emailVerifiedBody(EventTypeEmailVerified, ""))

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestEmailVerifiedHandler_RejectsNonPost(t *testing.T) {
	s, _ := newEmailVerifiedServer(t, emailVerifiedUser())
	req := httptest.NewRequest(http.MethodGet, "/v1/actions/email-verified", nil)
	rr := httptest.NewRecorder()

	s.emailVerifiedHandler(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}
