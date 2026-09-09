// Package utils contains shared helpers for the identity REST handlers
// (sessions, useridentities) that support staff users querying other users'
// resources via a field selector. The default behavior of those handlers is
// self-only (you can only see your own); when a field selector specifies a
// different target user UID, the request is allowed iff the caller can
// `get iam.miloapis.com/users/<targetUID>` on milo (verified via a
// SubjectAccessReview against the milo apiserver).
//
// Authorization is intentionally delegated to milo rather than checked
// in-process: this apiserver runs behind milo's front-proxy with an
// AlwaysAllowAuthorizer, treating milo as the single Policy Decision Point.
// The SAR call composes existing milo User RBAC instead of requiring this
// binary to ship its own group allow-list.
package utils

import (
	"context"
	"fmt"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apiserver/pkg/authentication/user"
)

// ExtractUserUIDFromFieldSelector extracts the userUID value from a field
// selector. Uses the kube-style nested path `status.userUID=<uid>` matching
// the Session / UserIdentity status field. Returns an error if the selector
// is empty or doesn't include a status.userUID requirement; callers should
// treat that as "no target user specified" and fall back to the
// authenticated user's UID.
func ExtractUserUIDFromFieldSelector(selector fields.Selector) (string, error) {
	if selector == nil || selector.Empty() {
		return "", fmt.Errorf("empty field selector")
	}
	if req, found := selector.RequiresExactMatch("status.userUID"); found {
		return req, nil
	}
	return "", fmt.Errorf("status.userUID not found in field selector")
}

// SubjectAccessReviewer is the minimal slice of the kube SAR client this
// package needs. The standard
// k8s.io/client-go/kubernetes.AuthorizationV1().SubjectAccessReviews()
// satisfies it; this interface is here so handlers can be unit-tested with
// a fake without pulling in the full clientset.
type SubjectAccessReviewer interface {
	Create(ctx context.Context, sar *authzv1.SubjectAccessReview, opts metav1.CreateOptions) (*authzv1.SubjectAccessReview, error)
}

// CanGetUser asks milo whether `caller` is authorized to GET the
// iam.miloapis.com/users/<targetUID> resource. It is the per-request authz
// gate for cross-user identity and session lookups.
//
// Composing on the existing User RBAC (rather than minting a new
// "list-sessions-any-user" permission) means staff/admin roles that already
// grant `get users` cluster-wide automatically get cross-user lookup, and
// finer-grained roles that only grant `get users/<X>` only see X's
// resources — same RBAC governs both layers.
func CanGetUser(ctx context.Context, sar SubjectAccessReviewer, caller user.Info, targetUID string) (bool, error) {
	if sar == nil {
		return false, fmt.Errorf("no SubjectAccessReviewer configured")
	}
	if caller == nil {
		return false, fmt.Errorf("no caller info in context")
	}
	review, err := sar.Create(ctx, &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   caller.GetName(),
			UID:    caller.GetUID(),
			Groups: caller.GetGroups(),
			Extra:  toAuthzExtra(caller.GetExtra()),
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:     "get",
				Group:    "iam.miloapis.com",
				Resource: "users",
				Name:     targetUID,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("subjectaccessreview against milo: %w", err)
	}
	return review.Status.Allowed, nil
}

// CanCreatePasskeyRegistrationLink asks milo whether `caller` may send a passkey
// recovery link to `targetUserName`.
//
// Same delegation as CanGetUser: milo is the single Policy Decision Point, and its
// OpenFGA authorizer resolves the identity-passkey-registration-links-editor role
// through the parent context below. The parent extras are what make the grant
// user-scoped rather than cluster-wide — the same convention the Project-scoped
// resources use.
func CanCreatePasskeyRegistrationLink(ctx context.Context, sar SubjectAccessReviewer, caller user.Info, targetUserName string) (bool, error) {
	if sar == nil {
		return false, fmt.Errorf("no SubjectAccessReviewer configured")
	}
	if caller == nil {
		return false, fmt.Errorf("no caller info in context")
	}

	extra := toAuthzExtra(caller.GetExtra())
	if extra == nil {
		extra = map[string]authzv1.ExtraValue{}
	}
	extra["iam.miloapis.com/parent-type"] = authzv1.ExtraValue{"User"}
	extra["iam.miloapis.com/parent-name"] = authzv1.ExtraValue{targetUserName}

	review, err := sar.Create(ctx, &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   caller.GetName(),
			UID:    caller.GetUID(),
			Groups: caller.GetGroups(),
			Extra:  extra,
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:     "create",
				Group:    "identity.miloapis.com",
				Resource: "passkeyregistrationlinks",
				Name:     targetUserName,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("subjectaccessreview against milo: %w", err)
	}
	return review.Status.Allowed, nil
}

// toAuthzExtra adapts user.Info.GetExtra() to the type expected by the
// authorization API.
func toAuthzExtra(extra map[string][]string) map[string]authzv1.ExtraValue {
	if len(extra) == 0 {
		return nil
	}
	out := make(map[string]authzv1.ExtraValue, len(extra))
	for k, v := range extra {
		out[k] = authzv1.ExtraValue(v)
	}
	return out
}
