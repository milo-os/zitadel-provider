package httpactionsserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// passkeyRemovedHandler notifies a user that a passkey was removed from their
// account.
//
// Variables are exactly UserName, RemovedTime, and optionally PasskeyName —
// pinned by the approved passkey-removed design. PasskeyName is OMITTED when
// unavailable, never sent empty: an empty value renders as "Passkey name:"
// followed by nothing, which is the defect that design removed.
func (s *Server) passkeyRemovedHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context()).WithName("passkeyRemovedHandler")
	log.Info("Handling passkey-removed request", "method", r.Method, "remoteAddr", r.RemoteAddr)

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

	// The removal event reuses the passkey-added envelope: same aggregateID,
	// event_type, created_at and event_payload.webAuthNTokenId fields.
	var req passkeyAddedRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		log.Error(err, "Failed to unmarshal request body")
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if req.EventType != EventTypePasskeyRemoved {
		log.Info("Ignoring event with unexpected type", "eventType", req.EventType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ignored"))
		return
	}

	// AggregateID is the SUBJECT; UserID is the event creator. For proxied
	// writes they differ, and passkey_added.go documents a live-fire case where
	// using UserID produced zero notifications for every real enrollment.
	userID := req.AggregateID
	if userID == "" {
		log.Error(nil, "Missing aggregateID in payload")
		http.Error(w, "userID not found in payload", http.StatusBadRequest)
		return
	}

	if err := sendPasskeyRemovedEmail(r.Context(), log, s, userID, req.CreatedAt, req.EventPayload.WebAuthNTokenID); err != nil {
		// Logged, not returned: Zitadel only needs the ack. Established
		// fire-and-forget posture of every handler here.
		log.Error(err, "Failed to send passkey-removed notification email", "userId", userID)
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("success"))
}

// sendPasskeyRemovedEmail looks up the User by Zitadel userID and creates an
// Email for the user-passkey-removed template.
func sendPasskeyRemovedEmail(ctx context.Context, log logr.Logger, s *Server, userID, removedAt, tokenID string) error {
	if s.config.PasskeyRemovedEmailTemplate == "" {
		log.V(1).Info("PasskeyRemovedEmailTemplate not configured; skipping notification")
		return nil
	}

	user := &iamv1alpha1.User{}
	if err := s.k8sClient.Get(ctx, client.ObjectKey{Name: userID}, user); err != nil {
		return fmt.Errorf("failed to get User %q: %w", userID, err)
	}

	displayName := strings.TrimSpace(user.Spec.GivenName + " " + user.Spec.FamilyName)
	if displayName == "" {
		displayName = user.Spec.Email
	}

	removedDisplay := removedAt
	if t, err := time.Parse(time.RFC3339Nano, removedAt); err == nil {
		removedDisplay = t.UTC().Format("Jan 2, 2006 at 15:04 UTC")
	}

	vars := make([]notificationv1alpha1.EmailVariable, 0, 3)
	vars = append(vars,
		notificationv1alpha1.EmailVariable{Name: "UserName", Value: displayName},
		notificationv1alpha1.EmailVariable{Name: "RemovedTime", Value: removedDisplay},
	)
	// Always sent, "" when unknown — the contract passkey_added.go uses for
	// Browser/Device. The template renders this row unconditionally, so an
	// omitted variable renders Go's `<no value>` into the text body.
	vars = append(vars, notificationv1alpha1.EmailVariable{
		Name:  "PasskeyName",
		Value: passkeyNameFromMetadata(ctx, s.zitadelClient, userID, tokenID),
	})

	email := &notificationv1alpha1.Email{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Email",
			APIVersion: "notification.miloapis.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("passkey-removed-%s", uuid.NewUUID()),
			Namespace: s.config.NotificationNamespace,
		},
		Spec: notificationv1alpha1.EmailSpec{
			TemplateRef: notificationv1alpha1.TemplateReference{
				Name: s.config.PasskeyRemovedEmailTemplate,
			},
			Recipient: notificationv1alpha1.EmailRecipient{
				UserRef: notificationv1alpha1.EmailUserReference{Name: user.Name},
			},
			Variables: vars,
			Priority:  notificationv1alpha1.EmailPriorityHigh,
		},
	}

	if err := s.k8sClient.Create(ctx, email); err != nil {
		return fmt.Errorf("failed to create passkey-removed Email resource: %w", err)
	}
	return nil
}

// passkeyNameFromMetadata returns the removed passkey's display name, or "" if
// it cannot be established.
//
// The Zitadel removal event carries only a token ID, so the name is recovered
// from the passkey:<tokenID>:created metadata entry auth-ui writes at
// enrollment. Every failure mode is non-fatal by design — the removal
// notification matters more than the name inside it — and there are five:
//
//  1. the Zitadel client is not configured
//  2. the metadata RPC fails
//  3. the key is absent, e.g. a passkey enrolled before the convention existed
//  4. the value is a legacy bare ISO date rather than JSON
//  5. the value is malformed JSON
//
// All five return "", which the caller sends as the variable's value.
func passkeyNameFromMetadata(ctx context.Context, api zitadel.API, userID, tokenID string) string {
	if api == nil || tokenID == "" {
		return ""
	}
	entries, err := api.ListUserMetadata(ctx, userID)
	if err != nil {
		return ""
	}

	want := fmt.Sprintf("passkey:%s:created", tokenID)
	for _, e := range entries {
		if e.Key != want {
			continue
		}
		var payload struct {
			Name string `json:"name"`
		}
		// A legacy bare ISO value fails here, which is the intended degradation.
		if err := json.Unmarshal([]byte(e.Value), &payload); err != nil {
			return ""
		}
		return payload.Name
	}
	return ""
}
