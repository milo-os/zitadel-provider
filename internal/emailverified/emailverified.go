// Package emailverified is the ONLY writer of the iam User status.emailVerification field.
// milo controllers read it (the waitlist mailer waits on it); nothing in milo sets it.
//
// Write discipline (Wave 0 W0-C10): status is written with Status().Update, never a merge
// patch — a bare merge patch would replace status wholesale and silently drop a concurrent
// writer's fields. So: read, set this one field, Update, retry on 409.
package emailverified

import (
	"context"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Desired returns the state Set would write, so callers holding a cached User can
// decide whether a write is needed without a round trip (the sweeper does this).
func Desired(verified bool) iamv1alpha1.EmailVerificationState {
	if verified {
		return iamv1alpha1.EmailVerificationStateVerified
	}
	return iamv1alpha1.EmailVerificationStateUnverified
}

// IsVerified reports whether the user's address is recorded as verified. Empty means
// this provider has not synced the user yet, which is not proof of anything, so it
// reports false exactly as an explicit Unverified does.
func IsVerified(user *iamv1alpha1.User) bool {
	return user != nil && user.Status.EmailVerification == iamv1alpha1.EmailVerificationStateVerified
}

// NeedsUpdate reports whether Set would change anything for this (possibly cached) User.
func NeedsUpdate(user *iamv1alpha1.User, verified bool) bool {
	return user.Status.EmailVerification != Desired(verified)
}

// Set records `verified` on the named User. Returns changed=false when the stored
// field already matches (no write issued).
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
		user.Status.EmailVerification = Desired(verified)
		if err := c.Status().Update(ctx, user); err != nil {
			return err
		}
		changed = true
		return nil
	})
	return changed, err
}
