package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	// DefaultAbandonedRetention is how long an unverified account is kept before
	// it becomes eligible for collection.
	DefaultAbandonedRetention = 30 * 24 * time.Hour
	// DefaultAbandonedGCInterval is how often the sweep runs.
	DefaultAbandonedGCInterval = 6 * time.Hour
)

var (
	abandonedScanned = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_abandoned_gc_scanned_total",
		Help: "Zitadel human users examined by the abandoned-account sweep.",
	})
	abandonedEligible = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_abandoned_gc_eligible_total",
		Help: "Unverified accounts past the retention window. In dry-run this is the blast radius; read it before disabling dry-run.",
	})
	abandonedDeleted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_abandoned_gc_deleted_total",
		Help: "Abandoned accounts actually deleted.",
	})
	abandonedSkippedIDP = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_abandoned_gc_skipped_idp_total",
		Help: "Accounts past the retention window that were spared because they carry an external IdP link.",
	})

	// verifiedNoCredential measures the class recovery exists for: a proven address
	// with nothing that can sign in. Counted, never collected — deleting a verified
	// account would race the recovery mail that turns it back into a working one
	// (spec §6). Revisit trigger: 50.
	verifiedNoCredential = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "zitadel_provider_verified_no_credential_accounts",
		Help: "Verified accounts with no passkey, password or IdP link — reachable only through recovery (Phase C, C9). Counted, never collected.",
	})
	abandonedErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_abandoned_gc_errors_total",
		Help: "Errors encountered while collecting abandoned accounts.",
	})
)

func init() {
	metrics.Registry.MustRegister(abandonedScanned, abandonedEligible, abandonedDeleted, abandonedSkippedIDP, abandonedErrors,
		verifiedNoCredential)
}

// ZitadelUserReaper is the narrow surface the sweep needs.
type ZitadelUserReaper interface {
	ListHumanUsers(ctx context.Context, offset uint64, limit uint32) ([]zitadel.User, int, error)
	ListIDPLinks(ctx context.Context, userID string) ([]zitadel.IDPLink, error)
	DeleteUser(ctx context.Context, userID string) error
	// ListAuthMethodTypes backs the C9 gauge; the sweep never acts on its result.
	ListAuthMethodTypes(ctx context.Context, userID string) ([]string, error)
}

// usableCredentials are the Zitadel AuthenticationMethodType names that can actually
// start a session. otpEmail is deliberately absent: it is enrolled on every Phase B
// account and C2 settled that it is not a login method, so counting it would hide
// exactly the class this gauge exists to measure.
var usableCredentials = map[string]struct{}{
	"AUTHENTICATION_METHOD_TYPE_PASSWORD": {},
	"AUTHENTICATION_METHOD_TYPE_PASSKEY":  {},
	"AUTHENTICATION_METHOD_TYPE_IDP":      {},
}

// hasUsableCredential reports whether any of the user's enrolled methods can sign in.
func hasUsableCredential(methods []string) bool {
	for _, m := range methods {
		if _, ok := usableCredentials[m]; ok {
			return true
		}
	}
	return false
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users,verbs=get;list;watch;delete

// AbandonedUserGC deletes accounts abandoned before email verification.
//
// Such an account owns one Zitadel user, one milo User, and the User's
// owner-referenced children (two PolicyBindings and a UserPreference), which
// Kubernetes garbage-collects with it. No organization, membership or quota.
//
// ORDERING IS NOT OPTIONAL: delete the Zitadel user FIRST, then the milo User.
// UserSweeper recreates a User for every Zitadel human user on every tick, so
// the reverse order lets the next sweep resurrect it and the two controllers
// fight indefinitely, with zitadel_provider_user_sweep_created_total as the only
// symptom.
type AbandonedUserGC struct {
	Client  client.Client
	Zitadel ZitadelUserReaper

	// Interval between sweeps. Non-positive disables the sweep entirely.
	Interval time.Duration
	// Retention is how long an unverified account is kept. Non-positive
	// disables the sweep: it must never be read as "delete everything".
	Retention time.Duration
	// DryRun reports what would be collected without deleting anything. Defaults
	// true: this deletes user accounts, so read the eligible counter first.
	//
	// The sweep selects on Zitadel's IsEmailVerified, and nobody has confirmed
	// what that reads for an account registered through Google or GitHub. That
	// used to make this dangerous: if social-IdP emails surfaced as false, the
	// sweep deleted legitimate users who simply never used a password.
	//
	// Accounts carrying an external IdP link are now skipped outright, so the
	// outcome no longer depends on that unknown. Deletion is still permanent:
	// inspect who is in zitadel_provider_abandoned_gc_eligible_total rather than
	// trusting the count, and check that
	// zitadel_provider_abandoned_gc_skipped_idp_total is non-zero — a flat zero
	// against a real population means the link lookup is not doing its job.
	DryRun bool

	// now is overridable in tests.
	now func() time.Time
}

func (g *AbandonedUserGC) Start(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("abandoned-user-gc")

	if g.Interval <= 0 || g.Retention <= 0 {
		log.Info("Abandoned-account GC disabled",
			"interval", g.Interval, "retention", g.Retention)
		return nil
	}
	log.Info("Starting abandoned-account GC",
		"interval", g.Interval, "retention", g.Retention, "dryRun", g.DryRun)

	ticker := time.NewTicker(g.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := g.sweepOnce(ctx); err != nil {
				log.Error(err, "Abandoned-account sweep failed")
			}
		}
	}
}

func (g *AbandonedUserGC) sweepOnce(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("abandoned-user-gc")
	cutoff := g.clock().Add(-g.Retention)

	var offset uint64
	var eligible, deleted, noCredential int

	for {
		users, raw, err := g.Zitadel.ListHumanUsers(ctx, offset, sweepPageSize)
		if err != nil {
			abandonedErrors.Inc()
			return fmt.Errorf("list human users at offset %d: %w", offset, err)
		}

		for _, u := range users {
			abandonedScanned.Inc()

			// C9 visibility, not a collection decision: measure the verified accounts
			// that cannot sign in. One RPC per VERIFIED user per GC interval (6h) —
			// unverified users are the sweep's own business and cost nothing here.
			if u.IsEmailVerified {
				methods, err := g.Zitadel.ListAuthMethodTypes(ctx, u.ID)
				if err != nil {
					// An unreadable method list is not evidence that there are none.
					abandonedErrors.Inc()
					log.Error(err, "Skipping C9 gauge for account: could not read auth methods", "userID", u.ID)
				} else if !hasUsableCredential(methods) {
					noCredential++
				}
			}

			if !g.isAbandoned(u, cutoff) {
				continue
			}
			// Never collect an account that came from an external IdP.
			//
			// isAbandoned selects on Zitadel's IsEmailVerified, and nobody has
			// confirmed what that reads for a Google or GitHub registration. If
			// it reports false for them, the sweep deletes users whose address
			// their provider verified years ago — permanently. Checking for a
			// link makes the outcome independent of that unknown instead of
			// conditional on it: whatever IsEmailVerified says, a social account
			// is never a candidate.
			//
			// The check runs here rather than inside isAbandoned because it is
			// an API call. Only accounts already past the retention window and
			// already unverified reach it, so it costs one request per
			// candidate, not per user.
			linked, err := g.hasIDPLink(ctx, u.ID)
			if err != nil {
				// Skip, do not delete. An unreadable link list is not evidence
				// that there are none, and this loop's mistakes are not
				// recoverable.
				abandonedErrors.Inc()
				log.Error(err, "Skipping account: could not read IdP links", "userID", u.ID)
				continue
			}
			if linked {
				abandonedSkippedIDP.Inc()
				log.V(1).Info("Skipping account with an external IdP link", "userID", u.ID)
				continue
			}

			eligible++
			abandonedEligible.Inc()

			if g.DryRun {
				log.Info("DRY RUN: would collect abandoned unverified account",
					"userID", u.ID, "createdAt", u.CreatedAt)
				continue
			}
			if err := g.collect(ctx, u.ID); err != nil {
				abandonedErrors.Inc()
				log.Error(err, "Failed to collect abandoned account", "userID", u.ID)
				continue
			}
			deleted++
			abandonedDeleted.Inc()
			log.Info("Collected abandoned unverified account", "userID", u.ID)
		}

		if raw < sweepPageSize {
			break
		}
		offset += uint64(raw)
	}

	// Set after the page loop so the gauge always reflects a whole sweep rather than
	// a partial one.
	verifiedNoCredential.Set(float64(noCredential))

	log.Info("Abandoned-account sweep complete",
		"eligible", eligible, "deleted", deleted, "dryRun", g.DryRun,
		"verifiedNoCredential", noCredential)
	return nil
}

// hasIDPLink reports whether the account was registered through an external
// identity provider.
func (g *AbandonedUserGC) hasIDPLink(ctx context.Context, userID string) (bool, error) {
	links, err := g.Zitadel.ListIDPLinks(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("list idp links for %s: %w", userID, err)
	}
	return len(links) > 0, nil
}

// isAbandoned reports whether an account is unverified and past the window.
func (g *AbandonedUserGC) isAbandoned(u zitadel.User, cutoff time.Time) bool {
	if u.IsEmailVerified {
		return false
	}
	// A zero CreatedAt means the API reported no creation date. Treat that as
	// unknown age and skip: guessing here deletes accounts of unknown vintage.
	if u.CreatedAt.IsZero() {
		return false
	}
	return u.CreatedAt.Before(cutoff)
}

// collect deletes the Zitadel user, then the milo User.
//
// The order is the whole point — see the type comment. Deleting milo first
// means UserSweeper recreates it on the next tick.
func (g *AbandonedUserGC) collect(ctx context.Context, userID string) error {
	if err := g.Zitadel.DeleteUser(ctx, userID); err != nil {
		return fmt.Errorf("delete zitadel user %q: %w", userID, err)
	}

	user := &iammiloapiscomv1alpha1.User{}
	user.SetName(userID)
	if err := g.Client.Delete(ctx, user); err != nil && !apierrors.IsNotFound(err) {
		// The Zitadel user is already gone, so UserSweeper will not recreate
		// this User; the next sweep retries the milo side.
		return fmt.Errorf("delete milo user %q: %w", userID, err)
	}
	return nil
}

func (g *AbandonedUserGC) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}
