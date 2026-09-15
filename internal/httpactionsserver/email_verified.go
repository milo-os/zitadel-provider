package httpactionsserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"go.miloapis.com/auth-provider-zitadel/internal/emailverified"
)

// EventTypeEmailVerified and EventTypeEmailChanged are the raw Zitadel Actions v2
// eventstore event types this handler is bound to. Names confirmed from the vendored
// Zitadel module (internal/repository/user/human_email.go:16-17, which composes them
// from the "user.human.email." prefix), matching the user.human.<domain>.<verb> scheme
// the passkey constants above already follow.
//
// Verification is the whole ownership invariant Phase B built on, so both directions
// matter: an address that CHANGES is unproven again until Zitadel says otherwise.
const (
	EventTypeEmailVerified = "user.human.email.verified"
	EventTypeEmailChanged  = "user.human.email.changed"
)

// emailVerifiedRequest models the Actions v2 webhook envelope for the two email events.
//
// AggregateID is the subject — the human whose address changed. UserID is the event
// creator, kept only for logging; see passkeyAddedRequest's doc comment for why those
// are not interchangeable.
type emailVerifiedRequest struct {
	AggregateID string `json:"aggregateID"`
	EventType   string `json:"event_type"`
	CreatedAt   string `json:"created_at"`
	UserID      string `json:"userID"`
}

// emailVerifiedHandler writes the User's EmailVerification field from Zitadel's email
// events. It is one of three call sites for the same writer — provisioning sets the
// initial value and the sweeper reconciles it — so a missed event self-heals within
// one sweep interval rather than leaving a user permanently unwelcomed.
//
// Structurally identical to passkeyAddedHandler: validate → unmarshal → check event
// type → resolve the subject → write. Unlike that handler this one does surface
// failures, because the field is the state milo's controllers gate on: a silent
// 200 on a failed write would leave the reader waiting on a fact we dropped.
func (s *Server) emailVerifiedHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context()).WithName("emailVerifiedHandler")
	log.Info("Handling email-verified request", "method", r.Method, "remoteAddr", r.RemoteAddr)

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

	var req emailVerifiedRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		log.Error(err, "Failed to unmarshal request body")
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	var verified bool
	switch req.EventType {
	case EventTypeEmailVerified:
		verified = true
	case EventTypeEmailChanged:
		verified = false
	default:
		log.Error(nil, "Unsupported event type", "eventType", req.EventType)
		http.Error(w, fmt.Sprintf("unsupported event type: %s", req.EventType), http.StatusBadRequest)
		return
	}

	userID := req.AggregateID
	if userID == "" {
		log.Error(nil, "User ID not found in payload", "eventCreatorUserId", req.UserID)
		http.Error(w, "userID not found in payload", http.StatusBadRequest)
		return
	}

	// The User is provisioned from a different Zitadel event, so it can still be
	// moments behind this one.
	if _, err := s.getUserWithRetry(r.Context(), userID); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("No User for email event", "userId", userID, "eventType", req.EventType)
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		log.Error(err, "Failed to read User", "userId", userID)
		http.Error(w, "failed to read user", http.StatusInternalServerError)
		return
	}

	changed, err := emailverified.Set(r.Context(), s.k8sClient, userID, verified)
	if err != nil {
		log.Error(err, "Failed to write EmailVerification field", "userId", userID)
		http.Error(w, "failed to update user", http.StatusInternalServerError)
		return
	}

	log.Info("Recorded EmailVerification field",
		"userId", userID, "eventType", req.EventType, "verified", verified, "changed", changed)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("success"))
}
