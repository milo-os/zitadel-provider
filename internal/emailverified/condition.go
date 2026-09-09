// Package emailverified is the ONLY writer of the iam User "EmailVerified" condition.
// milo controllers read it (the waitlist mailer waits on it); nothing in milo sets it.
//
// Write discipline (Wave 0 W0-C10): milo merges conditions with meta.SetStatusCondition and
// writes with Status().Update; a bare merge patch would replace status.conditions wholesale
// and silently drop a concurrent writer's condition. So: read, merge, Update, retry on 409.
package emailverified

import (
	"context"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const conditionType = string(iamv1alpha1.UserEmailVerifiedCondition)

// Desired returns the condition Set would write, so callers holding a cached User can
// decide whether a write is needed without a round trip (the sweeper does this).
func Desired(verified bool) metav1.Condition {
	if verified {
		return metav1.Condition{Type: conditionType, Status: metav1.ConditionTrue,
			Reason: iamv1alpha1.UserEmailVerifiedReason, Message: "Email address verified by the auth provider"}
	}
	return metav1.Condition{Type: conditionType, Status: metav1.ConditionFalse,
		Reason: iamv1alpha1.UserEmailNotVerifiedReason, Message: "Email address not verified"}
}

// IsTrue reports whether the user's address is recorded as verified.
func IsTrue(user *iamv1alpha1.User) bool {
	return user != nil && meta.IsStatusConditionTrue(user.Status.Conditions, conditionType)
}

// NeedsUpdate reports whether Set would change anything for this (possibly cached) User.
func NeedsUpdate(user *iamv1alpha1.User, verified bool) bool {
	cur := meta.FindStatusCondition(user.Status.Conditions, conditionType)
	want := Desired(verified)
	return cur == nil || cur.Status != want.Status || cur.Reason != want.Reason
}

// Set records `verified` on the named User. Returns changed=false when the stored
// condition already matches (no write issued).
func Set(ctx context.Context, c client.Client, userName string, verified bool) (bool, error) {
	changed := false
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		user := &iamv1alpha1.User{}
		if err := c.Get(ctx, client.ObjectKey{Name: userName}, user); err != nil {
			return err
		}
		if !NeedsUpdate(user, verified) {
			changed = false
			return nil
		}
		meta.SetStatusCondition(&user.Status.Conditions, Desired(verified))
		if err := c.Status().Update(ctx, user); err != nil {
			return err
		}
		changed = true
		return nil
	})
	return changed, err
}
