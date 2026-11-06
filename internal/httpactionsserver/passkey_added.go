package httpactionsserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.miloapis.com/auth-provider-zitadel/internal/userprovision"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
)

// EventTypePasskeyVerified is the raw Zitadel Actions v2 eventstore event
// type this handler is bound to: it fires when a WebAuthn passwordless
// ceremony COMPLETES (the credential becomes usable), and its payload
// (zitadel's HumanWebAuthNVerifiedEvent, see
// internal/repository/user/human_mfa_web_auth_n.go in
// github.com/zitadel/zitadel@v1.80.0-v2.20.0.20250619094244-3a4298c1794a)
// carries the user-assigned name as webAuthNTokenName. This is deliberately
// NOT EventTypePasskeyAdded: .added fires at enrollment START — including
// abandoned attempts that never complete — and its payload has no name at
// all (see EventTypePasskeyAdded's doc comment). Confirmed live against a
// local Zitadel v4.12.2 instance on 2026-07-21: an Actions v2 target
// condition bound to "user.human.passwordless.token.verified" returns 200,
// while "user.human.mfa.token.verified" (a plausible-looking wrong guess)
// 404s — v4.12.2 is still discriminating on the exact event-type string.
const EventTypePasskeyVerified = "user.human.passwordless.token.verified"

// EventTypePasskeyAdded is confirmed live and bindable the same way
// (2026-07-21 probe: 200), but deliberately unhandled here: it fires at
// enrollment start rather than completion (abandoned WebAuthn ceremonies
// still emit it) and its payload — zitadel's HumanWebAuthNAddedEvent
// (webAuthNTokenId, challenge, rpID) — carries no passkey name, so it
// cannot populate the PasskeyName variable the notification needs.
const EventTypePasskeyAdded = "user.human.passwordless.token.added"

// EventTypePasskeyRemoved is confirmed live and bindable the same way, but
// unhandled here: no user-passkey-removed notification template exists yet
// (only user-passkey-added has been merged). Wiring a removed handler is an
// explicit open decision left for whoever adds that template — do not
// invent a second template to fill it.
const EventTypePasskeyRemoved = "user.human.passwordless.token.removed"

// passkeyAddedRequest models the Actions v2 webhook envelope for
// EventTypePasskeyVerified — kept as "passkeyAdded*" because "passkey
// added" is the user-facing notification concept (and the email template's
// name); only the bound event and its payload parsing are token.verified's.
//
// IMPORTANT — creator vs subject: UserID is the event CREATOR, not the
// enrolled user. AggregateID is the subject: the `user` eventstore
// aggregate this event is about, i.e. the human who actually enrolled the
// passkey. This is NOT the same field for every user-aggregate event —
// createUserAccountRequest's top-level UserID works fine because
// self-registration has no proxying actor — but VerifyPasskeyRegistration
// is called server-side by auth-ui's login-client service account on the
// user's behalf, making token.verified a proxied write. Confirmed against
// a real enrollment on a local Zitadel v4.12.2 instance, 2026-07-21:
// UserID resolved to the login-client service user (id
// 377553834484760638, no User CR exists for a service account) while
// AggregateID resolved to the actual enrolled human (id
// 378672530606522402). The original version of this handler preferred
// UserID here, so the User CR lookup 404'd and every real enrollment
// silently produced zero Email resources.
//
// Compare internal/httpactionsserver/session_added.go's oidc_session.added
// handling: it resolves the target user from EventPayload.UserID (nested
// in the raw eventstore session-added payload, a different field from this
// envelope's top-level UserID) and is unaffected by this asymmetry — a
// session is always created by the human who owns it, so creator and
// subject coincide there. Do not assume envelope UserID means "subject"
// for any future Actions v2 handler without checking which shape applies.
type passkeyAddedRequest struct {
	AggregateID string `json:"aggregateID"`
	EventType   string `json:"event_type"`
	CreatedAt   string `json:"created_at"`
	// UserID is the event creator/actor (see the doc comment above) — kept
	// only for logging/audit visibility. Never use it to resolve the
	// notification's target user; use AggregateID.
	UserID       string `json:"userID"`
	EventPayload struct {
		WebAuthNTokenID   string `json:"webAuthNTokenId"`
		WebAuthNTokenName string `json:"webAuthNTokenName,omitempty"`
		Name              string `json:"name,omitempty"`
	} `json:"event_payload"`
}

// passkeyName picks the passkey's display name off the parsed payload:
// the confirmed webAuthNTokenName field first, falling back to the
// speculative "name" field (see passkeyAddedRequest's doc comment).
func (req passkeyAddedRequest) passkeyName() string {
	if req.EventPayload.WebAuthNTokenName != "" {
		return req.EventPayload.WebAuthNTokenName
	}
	return req.EventPayload.Name
}

// passkeyAddedHandler handles EventTypePasskeyVerified (the completed
// passkey enrollment ceremony — see its doc comment for why not .added) and
// sends a best-effort lifecycle notification email. Structurally identical
// to sessionAddedHandler minus the session-history comparison: validate →
// unmarshal → check event type → resolve userID → best-effort notify.
// Notification failures (e.g. the User CR hasn't propagated yet) are
// logged, not surfaced as an HTTP error — Zitadel only needs the 200 ack
// that its webhook was received, the same fire-and-forget posture
// sessionAddedHandler uses for its own suspicious-login email.
func (s *Server) passkeyAddedHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context()).WithName("passkeyAddedHandler")
	log.Info("Handling passkey-added request", "method", r.Method, "remoteAddr", r.RemoteAddr)

	if r.Method != http.MethodPost {
		log.Error(nil, "Method not allowed", "method", r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error(err, "Failed to read request body")
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := s.validateSignature(bodyBytes, r.Header.Get("Zitadel-Signature"), s.config.SigningKey); err != nil {
		log.Error(err, "Signature validation failed")
		http.Error(w, fmt.Sprintf("signature validation failed: %v", err), http.StatusUnauthorized)
		return
	}
	log.V(1).Info("Request signature validated successfully")

	var req passkeyAddedRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		log.Error(err, "Failed to unmarshal request body")
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	log.V(1).Info("Request body unmarshaled successfully")

	if req.EventType != EventTypePasskeyVerified {
		log.Error(nil, "Unsupported event type", "eventType", req.EventType)
		http.Error(w, fmt.Sprintf("unsupported event type: %s", req.EventType), http.StatusBadRequest)
		return
	}

	// AggregateID is the subject (the enrolled human), not req.UserID (the
	// event creator — auth-ui's login-client service account for this
	// proxied write). See passkeyAddedRequest's doc comment for the
	// live-fire evidence; do not fall back to UserID here, or a momentarily
	// empty AggregateID would silently resolve to the wrong user again.
	userID := req.AggregateID
	if userID == "" {
		log.Error(nil, "User ID not found in payload", "eventCreatorUserId", req.UserID)
		http.Error(w, "userID not found in payload", http.StatusBadRequest)
		return
	}

	if err := sendPasskeyAddedEmail(r.Context(), log, s, userID, req.CreatedAt, req.passkeyName()); err != nil {
		log.Error(err, "Failed to send passkey-added notification email", "userId", userID)
	}

	s.recordUserEvent(r.Context(), log, userID, userprovision.EventReasonPasskeyEnrolled, passkeyEventMessage("added", req.passkeyName()))

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("success"))
}

// sendPasskeyAddedEmail looks up the User resource by Zitadel userID and
// creates an Email resource for the user-passkey-added template. The
// template's pinned variable contract is exactly UserName, PasskeyName,
// AddedTime, Browser, Device — no more, no less.
//
// PasskeyName comes from EventTypePasskeyVerified's webAuthNTokenName field
// (see passkeyAddedRequest.passkeyName). Browser and Device have no source
// at all in this event — Zitadel's HumanWebAuthNVerifiedEvent carries key
// material and the token name, not user-agent data — and are always left
// empty. This is a known gap, not a bug: the event this handler reacts to
// simply doesn't carry that data.
func sendPasskeyAddedEmail(ctx context.Context, log logr.Logger, s *Server, userID, addedAt, passkeyName string) error {
	if s.config.PasskeyAddedEmailTemplate == "" {
		log.Info("Passkey-added email template not configured; skipping notification")
		return nil
	}

	// Fetch the User resource — its name is the Zitadel aggregate ID.
	user := &iamv1alpha1.User{}
	if err := s.k8sClient.Get(ctx, client.ObjectKey{Name: userID}, user); err != nil {
		return fmt.Errorf("failed to get user %q: %w", userID, err)
	}

	displayName := strings.TrimSpace(user.Spec.GivenName + " " + user.Spec.FamilyName)
	if displayName == "" {
		displayName = user.Spec.Email
	}

	// Parse addedAt into a human-readable format; fall back to the raw string.
	addedDisplay := addedAt
	if t, err := time.Parse(time.RFC3339Nano, addedAt); err == nil {
		addedDisplay = t.UTC().Format("Jan 2, 2006 at 15:04 UTC")
	}

	email := &notificationv1alpha1.Email{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Email",
			APIVersion: "notification.miloapis.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("passkey-added-%s", uuid.NewUUID()),
			Namespace: s.config.NotificationNamespace,
		},
		Spec: notificationv1alpha1.EmailSpec{
			TemplateRef: notificationv1alpha1.TemplateReference{
				Name: s.config.PasskeyAddedEmailTemplate,
			},
			Recipient: notificationv1alpha1.EmailRecipient{
				UserRef: notificationv1alpha1.EmailUserReference{
					Name: user.Name,
				},
			},
			Variables: []notificationv1alpha1.EmailVariable{
				{Name: "UserName", Value: displayName},
				{Name: "PasskeyName", Value: passkeyName},
				{Name: "AddedTime", Value: addedDisplay},
				{Name: "Browser", Value: ""},
				{Name: "Device", Value: ""},
			},
			Priority: notificationv1alpha1.EmailPriorityHigh,
		},
	}

	if err := s.k8sClient.Create(ctx, email); err != nil {
		return fmt.Errorf("failed to create passkey-added Email resource: %w", err)
	}

	log.Info("Passkey-added notification email created", "userId", userID, "emailName", email.Name)
	return nil
}
