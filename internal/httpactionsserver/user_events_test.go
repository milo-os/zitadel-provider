package httpactionsserver

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.miloapis.com/auth-provider-zitadel/internal/userprovision"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const userEventTestUserID = "362926680773230861"

func newUserEventServer(t *testing.T, k8s client.Client) *Server {
	t.Helper()
	return &Server{
		config:            NewServerConfig(),
		k8sClient:         k8s,
		validateSignature: func([]byte, string, string) error { return nil },
	}
}

func listUserEvents(t *testing.T, k8s client.Client) []corev1.Event {
	t.Helper()
	events := &corev1.EventList{}
	if err := k8s.List(context.Background(), events, client.InNamespace(userprovision.EventNamespace)); err != nil {
		t.Fatalf("list events: %v", err)
	}
	return events.Items
}

// assertSingleUserEvent checks the one Event the activity pipeline depends on: it
// must point at the user's User (apiVersion/kind/name are what milo's User
// ActivityPolicy and the user-scoped Activity query key on) with the given reason.
func assertSingleUserEvent(t *testing.T, events []corev1.Event, reason, message string) {
	t.Helper()
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 Event, got %d: %+v", len(events), events)
	}
	e := events[0]
	want := corev1.ObjectReference{APIVersion: "iam.miloapis.com/v1alpha1", Kind: "User", Name: userEventTestUserID}
	got := e.InvolvedObject
	got.UID = ""
	if got != want {
		t.Errorf("involvedObject = %+v, want %+v", got, want)
	}
	if e.Reason != reason {
		t.Errorf("reason = %q, want %q", e.Reason, reason)
	}
	if e.Message != message {
		t.Errorf("message = %q, want %q", e.Message, message)
	}
	if e.Type != corev1.EventTypeNormal {
		t.Errorf("type = %q, want Normal", e.Type)
	}
	if e.Source.Component != "auth-provider-zitadel" || e.ReportingController != "auth-provider-zitadel" {
		t.Errorf("source.component = %q, reportingController = %q, want auth-provider-zitadel", e.Source.Component, e.ReportingController)
	}
	if e.Name == "" {
		t.Error("expected an explicit Event name (generateName is not expanded downstream)")
	}
	if e.LastTimestamp.IsZero() {
		t.Error("expected lastTimestamp to be set (the activity timestamp falls back to it)")
	}
}

func TestCreateUserAccountHandler_RecordsAccountCreatedEvent(t *testing.T) {
	const body = `{
		"aggregateID": "362926680773230861",
		"event_type": "user.human.added",
		"created_at": "2026-06-05T12:00:00Z",
		"userID": "362926680773230861",
		"event_payload": {"firstName":"Jane","lastName":"Doe","email":"jane@example.com"}
	}`
	post := func(s *Server) {
		req := httptest.NewRequest(http.MethodPost, "/v1/actions/create-user-account", bytes.NewBufferString(body))
		rr := httptest.NewRecorder()
		s.createUserAccountHandler(rr, req)
		if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
			t.Fatalf("unexpected status %d (%s)", rr.Code, rr.Body.String())
		}
	}

	t.Run("a new account records AccountCreated against the User", func(t *testing.T) {
		k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).WithStatusSubresource(&iamv1alpha1.User{}).Build()
		post(newUserEventServer(t, k8s))
		assertSingleUserEvent(t, listUserEvents(t, k8s), userprovision.EventReasonAccountCreated, "Account created")
	})

	t.Run("a retried webhook for an existing account records nothing", func(t *testing.T) {
		existing := &iamv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: userEventTestUserID}}
		k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(existing).Build()
		post(newUserEventServer(t, k8s))
		if events := listUserEvents(t, k8s); len(events) != 0 {
			t.Fatalf("expected no Event for an already-existing User, got %d", len(events))
		}
	})

	t.Run("a failed Event write does not fail provisioning", func(t *testing.T) {
		k8s := fake.NewClientBuilder().
			WithScheme(newTestScheme()).
			WithStatusSubresource(&iamv1alpha1.User{}).
			WithInterceptorFuncs(interceptor.Funcs{
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					if _, ok := obj.(*corev1.Event); ok {
						return errors.New("events unavailable")
					}
					return c.Create(ctx, obj, opts...)
				},
			}).
			Build()
		s := newUserEventServer(t, k8s)
		req := httptest.NewRequest(http.MethodPost, "/v1/actions/create-user-account", bytes.NewBufferString(body))
		rr := httptest.NewRecorder()
		s.createUserAccountHandler(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201 despite the Event failure, got %d (%s)", rr.Code, rr.Body.String())
		}
	})
}

func TestPasskeyHandlers_RecordUserEvents(t *testing.T) {
	user := &iamv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: userEventTestUserID}}

	t.Run("enrollment records PasskeyEnrolled with the passkey name", func(t *testing.T) {
		const body = `{"aggregateID":"362926680773230861","event_type":"user.human.passwordless.token.verified","created_at":"2026-07-21T12:00:00Z","userID":"377553834484760638","event_payload":{"webAuthNTokenId":"pk-abc123","webAuthNTokenName":"MacBook Touch ID"}}`
		k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(user).Build()
		postPasskeyAdded(t, newUserEventServer(t, k8s), body, http.StatusOK)
		assertSingleUserEvent(t, listUserEvents(t, k8s), userprovision.EventReasonPasskeyEnrolled, `Passkey "MacBook Touch ID" added`)
	})

	t.Run("enrollment without a name still records the event", func(t *testing.T) {
		const body = `{"aggregateID":"362926680773230861","event_type":"user.human.passwordless.token.verified","created_at":"2026-07-21T12:00:00Z","event_payload":{"webAuthNTokenId":"pk-abc123"}}`
		k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(user).Build()
		postPasskeyAdded(t, newUserEventServer(t, k8s), body, http.StatusOK)
		assertSingleUserEvent(t, listUserEvents(t, k8s), userprovision.EventReasonPasskeyEnrolled, "Passkey added")
	})

	t.Run("removal records PasskeyRemoved", func(t *testing.T) {
		const body = `{"aggregateID":"362926680773230861","event_type":"user.human.passwordless.token.removed","created_at":"2026-07-21T12:00:00Z","event_payload":{"webAuthNTokenId":"pk-abc123"}}`
		k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(user).Build()
		req := httptest.NewRequest(http.MethodPost, "/v1/actions/passkey-removed", bytes.NewBufferString(body))
		rr := httptest.NewRecorder()
		newUserEventServer(t, k8s).passkeyRemovedHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
		}
		// No Zitadel client in the test, so the name lookup comes back empty.
		assertSingleUserEvent(t, listUserEvents(t, k8s), userprovision.EventReasonPasskeyRemoved, "Passkey removed")
	})
}
