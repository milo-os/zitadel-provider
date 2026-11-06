package userprovision

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func eventScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = iammiloapiscomv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	return s
}

func TestRecordEvent(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(eventScheme()).Build()
	RecordEvent(context.Background(), c, logr.Discard(), "362926680773230861", "user-uid", EventReasonPasskeyEnrolled, `Passkey "YubiKey" added`)

	events := &corev1.EventList{}
	if err := c.List(context.Background(), events, client.InNamespace(EventNamespace)); err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events.Items) != 1 {
		t.Fatalf("expected 1 Event, got %d", len(events.Items))
	}
	e := events.Items[0]

	// milo's events proxy and the activity service don't expand generateName, so the
	// name must be set by us (and unique per call, like client-go's recorder).
	if !strings.HasPrefix(e.Name, "362926680773230861.") || len(e.Name) <= len("362926680773230861.") {
		t.Errorf("name = %q, want an explicit <user>.<suffix> name", e.Name)
	}
	if e.GenerateName != "" {
		t.Errorf("generateName = %q, want empty", e.GenerateName)
	}
	want := corev1.ObjectReference{APIVersion: "iam.miloapis.com/v1alpha1", Kind: "User", Name: "362926680773230861", UID: "user-uid"}
	if e.InvolvedObject != want {
		t.Errorf("involvedObject = %+v, want %+v", e.InvolvedObject, want)
	}
	// The User ActivityPolicy only accepts these reasons from this component.
	if e.Source.Component != EventComponent || e.ReportingController != EventComponent {
		t.Errorf("source.component = %q, reportingController = %q, want %q", e.Source.Component, e.ReportingController, EventComponent)
	}
	if e.Reason != EventReasonPasskeyEnrolled || e.Message != `Passkey "YubiKey" added` || e.Type != corev1.EventTypeNormal {
		t.Errorf("reason/message/type = %q/%q/%q", e.Reason, e.Message, e.Type)
	}
	if e.FirstTimestamp.IsZero() || e.LastTimestamp.IsZero() || e.Count != 1 {
		t.Errorf("timestamps/count not set: first=%v last=%v count=%d", e.FirstTimestamp, e.LastTimestamp, e.Count)
	}
}

func TestRecordEvent_CreateFailureIsSwallowed(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(eventScheme()).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
			return errors.New("events unavailable")
		},
	}).Build()
	// Must not panic or surface the error: callers are provisioning paths.
	RecordEvent(context.Background(), c, logr.Discard(), "u", "", EventReasonAccountCreated, "Account created")
}
