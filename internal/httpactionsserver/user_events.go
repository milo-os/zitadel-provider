package httpactionsserver

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.miloapis.com/auth-provider-zitadel/internal/userprovision"
)

// recordUserEvent records an activity Event against the user's User, looking the
// User up for its UID (passkey webhooks carry only the Zitadel ID). A lookup miss
// still records the event by name. See userprovision.RecordEvent; best effort,
// never fails the Zitadel action.
func (s *Server) recordUserEvent(ctx context.Context, log logr.Logger, userName, reason, message string) {
	var uid types.UID
	user := &iamv1alpha1.User{}
	if err := s.k8sClient.Get(ctx, client.ObjectKey{Name: userName}, user); err == nil {
		uid = user.UID
	} else {
		log.V(1).Info("Recording user event without UID; User lookup failed", "userName", userName, "reason", reason, "err", err)
	}
	userprovision.RecordEvent(ctx, s.k8sClient, log, userName, uid, reason, message)
}

// passkeyEventMessage is the Event message for a passkey enrollment or removal,
// naming the passkey when Zitadel reported a name.
func passkeyEventMessage(verb, passkeyName string) string {
	if passkeyName == "" {
		return fmt.Sprintf("Passkey %s", verb)
	}
	return fmt.Sprintf("Passkey %q %s", passkeyName, verb)
}
