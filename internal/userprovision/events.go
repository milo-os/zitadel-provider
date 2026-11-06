package userprovision

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Reasons of the Kubernetes Events recorded against a user's User resource.
// milo's iam.miloapis.com-user ActivityPolicy matches on these (eventRules), so
// they are a contract with that policy: rename one and its activity disappears.
const (
	EventReasonAccountCreated  = "AccountCreated"
	EventReasonPasskeyEnrolled = "PasskeyEnrolled"
	EventReasonPasskeyRemoved  = "PasskeyRemoved"
)

// EventComponent is the Event source and reporting controller. milo's User
// ActivityPolicy only accepts the reasons above from this component, and the
// activity service reports it as the activity's actor.
const EventComponent = "auth-provider-zitadel"

// EventNamespace holds Events about User, which is cluster-scoped. Kubernetes
// records events for cluster-scoped objects in "default", and milo's own
// controllers do the same for Projects.
const EventNamespace = "default"

// RecordEvent records a Kubernetes Event against the User named userName. userUID
// may be empty when the caller doesn't have it; the policy and the Activity feed key
// on the name. It takes the UID rather than reading the User so the sweep keeps its
// no-per-user-reads guarantee.
//
// Why an Event and not just the audit log: signup and passkey enrollment happen in
// Zitadel, so the only milo write they produce is made by this service (the User
// create, by a system identity the User ActivityPolicy ignores) or none at all
// (passkeys). The activity service turns these Events into activities on the
// user's own User, which the user's Activity feed includes.
//
// Best effort: a failure is logged and never returned, so callers never fail a
// provisioning step (or make Zitadel retry a webhook) over a missing activity.
func RecordEvent(ctx context.Context, c client.Client, log logr.Logger, userName string, userUID types.UID, reason, message string) {
	ref := corev1.ObjectReference{
		APIVersion: iammiloapiscomv1alpha1.SchemeGroupVersion.String(),
		Kind:       "User",
		Name:       userName,
		UID:        userUID,
	}

	now := time.Now()
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			// Named explicitly, the way client-go's event recorder does: milo's events
			// proxy and the activity service store Events without expanding
			// generateName, so a generated name would be stored empty.
			Name:      fmt.Sprintf("%s.%x", userName, now.UnixNano()),
			Namespace: EventNamespace,
		},
		InvolvedObject:      ref,
		Reason:              reason,
		Message:             message,
		Type:                corev1.EventTypeNormal,
		Source:              corev1.EventSource{Component: EventComponent},
		ReportingController: EventComponent,
		FirstTimestamp:      metav1.NewTime(now),
		LastTimestamp:       metav1.NewTime(now),
		Count:               1,
	}
	if err := c.Create(ctx, event); err != nil {
		log.Error(err, "Failed to record user event", "userName", userName, "reason", reason)
		return
	}
	log.V(1).Info("Recorded user event", "userName", userName, "reason", reason, "event", event.Name)
}
