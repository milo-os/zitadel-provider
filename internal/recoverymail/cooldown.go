package recoverymail

import (
	"context"
	"fmt"
	"time"

	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// capWindow is the span the per-hour cap is measured over. Fixed rather than
// configurable: two knobs that both mean "how often" invite an operator to set a
// cooldown and a cap that contradict each other.
const capWindow = time.Hour

// TooSoon reports whether another recovery mail for this user would exceed the
// configured budget.
//
// Recovery is inherently pre-authentication — the premise is a user who cannot
// authenticate — so the requester cannot be bound to the account, and a per-user
// budget is one of the only two controls that do apply. The other is the origin
// allowlist. Without this, a userId (which is not secret; it appears in tokens and
// API responses) was an unbounded High-priority mail primitive against any verified
// account, useful for burying a real security notification under volume and for
// damaging the sending domain's reputation for every other transactional mail.
//
// The source of truth is the Emails themselves rather than in-process state: both
// triggers create them, the webhook runs with replicas, and a counter in memory would
// reset on every rollout.
//
// The budget is per user AND per trigger. A self-serve flood must not deny support
// the backstop that exists precisely for when self-serve has failed the user; support
// is separately gated by a SubjectAccessReview, so its own cap is a sanity bound
// rather than a security control.
//
// A zero cooldown or a zero maxPerHour disables that half of the check.
func TooSoon(
	ctx context.Context,
	c client.Client,
	namespace, userID, requestedBy string,
	cooldown time.Duration,
	maxPerHour int,
) (bool, error) {
	if cooldown <= 0 && maxPerHour <= 0 {
		return false, nil
	}

	var sent notificationv1alpha1.EmailList
	if err := c.List(ctx, &sent,
		client.InNamespace(namespace),
		client.MatchingLabels{LabelUser: userID, LabelRequestedBy: requestedBy},
	); err != nil {
		// Never swallowed into "not too soon": an unreadable list is not evidence that
		// nothing was sent, and the caller fails closed on it.
		return false, fmt.Errorf("list recovery emails for rate limiting: %w", err)
	}

	now := time.Now()
	var inWindow int
	for i := range sent.Items {
		age := now.Sub(sent.Items[i].CreationTimestamp.Time)
		if cooldown > 0 && age < cooldown {
			return true, nil
		}
		if age < capWindow {
			inWindow++
		}
	}

	return maxPerHour > 0 && inWindow >= maxPerHour, nil
}
