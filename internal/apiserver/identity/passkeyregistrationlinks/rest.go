// Package passkeyregistrationlinks serves the admin backstop for account recovery:
// support asks for a passkey registration link, this resource mints the Zitadel code
// and mails it to the user's verified address.
//
// Create-only and virtual — nothing is persisted here. The durable record is the
// notification Email the create produces, labeled with the user, the requester and
// the reason; Status.EmailName points at it. There is no delete because Zitadel's v2
// API cannot revoke an issued code: it expires.
//
// The code is a bearer credential. It reaches the Email's Variables and nowhere else —
// not the returned object, not its name, not a log line, not an error.
package passkeyregistrationlinks

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.miloapis.com/auth-provider-zitadel/internal/apiserver/identity/utils"
	"go.miloapis.com/auth-provider-zitadel/internal/emailverified"
	"go.miloapis.com/auth-provider-zitadel/internal/recoverymail"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	milov1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// namePrefix identifies the returned object. It shares the Email's hash suffix so the
// two can be correlated without either carrying the code.
const namePrefix = "passkey-recovery-"

var passkeyRegistrationLinksGR = schema.GroupResource{
	Group: milov1alpha1.SchemeGroupVersion.Group, Resource: "passkeyregistrationlinks",
}

// Options is the wiring for New.
type Options struct {
	Z    zitadel.API
	Milo client.Client
	// MiloSAR is the authorization gate; milo is the single Policy Decision Point.
	MiloSAR utils.SubjectAccessReviewer
	// Enabled is --recovery-links-enabled. While false the create returns 503, so the
	// milo role can ship dormant and infra keeps the activation ordering.
	Enabled bool

	SupportTemplateName   string
	NotificationNamespace string
	// CompleteURL is where the mailed link lands. Parsed once in New so a malformed
	// value fails at startup rather than on a support engineer's first request.
	CompleteURL   string
	ExpiryMinutes int
}

type REST struct {
	Z       zitadel.API
	Milo    client.Client
	MiloSAR utils.SubjectAccessReviewer
	Enabled bool

	SupportTemplateName   string
	NotificationNamespace string
	ExpiryMinutes         int

	completeURL *url.URL
}

// New validates the options and builds the storage.
func New(opts Options) (*REST, error) {
	completeURL, err := url.Parse(opts.CompleteURL)
	if err != nil {
		return nil, fmt.Errorf("parse --account-recovery-complete-url: %w", err)
	}
	return &REST{
		Z: opts.Z, Milo: opts.Milo, MiloSAR: opts.MiloSAR, Enabled: opts.Enabled,
		SupportTemplateName:   opts.SupportTemplateName,
		NotificationNamespace: opts.NotificationNamespace,
		ExpiryMinutes:         opts.ExpiryMinutes,
		completeURL:           completeURL,
	}, nil
}

var _ rest.Creater = &REST{} //nolint:misspell
var _ rest.Storage = &REST{}
var _ rest.SingularNameProvider = &REST{}

func (r *REST) NamespaceScoped() bool   { return false }
func (r *REST) New() runtime.Object     { return &milov1alpha1.PasskeyRegistrationLink{} }
func (r *REST) GetSingularName() string { return "passkeyregistrationlink" }
func (r *REST) Destroy()                {}

// Create mints a passkey registration code for the target user and mails it.
func (r *REST) Create(
	ctx context.Context,
	obj runtime.Object,
	_ rest.ValidateObjectFunc,
	_ *metav1.CreateOptions,
) (runtime.Object, error) {
	link, ok := obj.(*milov1alpha1.PasskeyRegistrationLink)
	if !ok {
		klog.ErrorS(nil, "Unexpected object type in Create", "type", obj)
		return nil, apierrors.NewBadRequest("invalid object type")
	}

	if !r.Enabled {
		return nil, apierrors.NewServiceUnavailable("recovery links are disabled (--recovery-links-enabled=false)")
	}

	caller, ok := request.UserFrom(ctx)
	if !ok {
		return nil, apierrors.NewUnauthorized("no user in context")
	}

	target := link.Spec.UserRef.Name
	switch {
	case target == "":
		return nil, apierrors.NewBadRequest("spec.userRef.name is required")
	case strings.TrimSpace(link.Spec.Reason) == "":
		return nil, apierrors.NewBadRequest("spec.reason is required")
	case link.Spec.RequestedBy != caller.GetName():
		// requestedBy is the audit record; nobody may attribute a link to someone else.
		return nil, apierrors.NewBadRequest("spec.requestedBy must be the authenticated caller")
	}

	allowed, err := utils.CanCreatePasskeyRegistrationLink(ctx, r.MiloSAR, caller, target)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	if !allowed {
		return nil, apierrors.NewForbidden(passkeyRegistrationLinksGR, "",
			fmt.Errorf("not authorized to send a recovery link to user %q", target))
	}

	user := &iamv1alpha1.User{}
	if err := r.Milo.Get(ctx, client.ObjectKey{Name: target}, user); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, apierrors.NewNotFound(passkeyRegistrationLinksGR, target)
		}
		return nil, apierrors.NewInternalError(err)
	}

	if !emailverified.IsTrue(user) {
		// Support is a trusted caller, so this is a clear rejection rather than the
		// silent one the self-serve path gives: there is no enumeration risk here.
		return nil, apierrors.NewBadRequest(
			"the user's email address is not verified; ask them to sign up again to receive a verification link")
	}

	codeID, code, err := r.Z.CreatePasskeyRegistrationLink(ctx, target)
	if err != nil {
		klog.ErrorS(err, "Failed to create passkey registration link", "userID", target) // err carries no code
		return nil, translateErr(err, target)
	}

	email := recoverymail.Build(recoverymail.Input{
		User:          user,
		UserID:        target,
		CodeID:        codeID,
		Code:          code,
		ActionURL:     recoverymail.ActionURL(r.completeURL, target, codeID, code),
		TemplateName:  r.SupportTemplateName,
		Namespace:     r.NotificationNamespace,
		ExpiryMinutes: r.ExpiryMinutes,
		RequestedBy:   recoverymail.RequestedBySupport,

		RequestedByUser: caller.GetName(),
		Reason:          link.Spec.Reason,
	})

	if err := r.Milo.Create(ctx, email); err != nil && !apierrors.IsAlreadyExists(err) {
		// Never wrap err: an apiserver rejection can quote the object it rejected,
		// and that object carries the code.
		klog.ErrorS(nil, "Failed to create recovery Email", "userID", target,
			"reason", apierrors.ReasonForError(err))
		return nil, apierrors.NewInternalError(fmt.Errorf("create recovery email"))
	}

	out := link.DeepCopy()
	out.Name = namePrefix + strings.TrimPrefix(email.Name, "account-recovery-")
	out.Status = milov1alpha1.PasskeyRegistrationLinkStatus{
		UserUID:   string(user.UID),
		EmailName: email.Name,
		ExpiresAt: &metav1.Time{Time: time.Now().Add(time.Duration(r.ExpiryMinutes) * time.Minute)},
	}
	klog.V(2).InfoS("Sent passkey recovery link", "userID", target,
		"requestedBy", caller.GetName(), "emailName", email.Name)
	return out, nil
}

func translateErr(err error, name string) error {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound:
			return apierrors.NewNotFound(passkeyRegistrationLinksGR, name)
		case codes.PermissionDenied:
			return apierrors.NewForbidden(passkeyRegistrationLinksGR, name, nil)
		case codes.Unauthenticated:
			return apierrors.NewUnauthorized("unauthenticated")
		case codes.InvalidArgument:
			return apierrors.NewBadRequest(st.Message())
		case codes.DeadlineExceeded, codes.Unavailable:
			return apierrors.NewServiceUnavailable("zitadel unavailable")
		default:
			return apierrors.NewInternalError(err)
		}
	}
	return err
}
