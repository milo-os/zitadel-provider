package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"go.miloapis.com/auth-provider-zitadel/internal/emailverified"
	"go.miloapis.com/auth-provider-zitadel/internal/userprovision"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
)

const sweepPageSize = 100

var (
	sweepScanned = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_user_sweep_scanned_total",
		Help: "Eligible Zitadel human users scanned by the invariant sweeper.",
	})
	sweepMissing = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_user_sweep_missing_total",
		Help: "Zitadel users found without a corresponding User resource.",
	})
	sweepCreated = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_user_sweep_created_total",
		Help: "User resources created by the invariant sweeper.",
	})
	sweepErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_user_sweep_errors_total",
		Help: "Sweeps aborted by an error.",
	})
	sweepLastSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "zitadel_provider_user_sweep_last_success_timestamp_seconds",
		Help: "Unix time of the last fully successful sweep.",
	})
	sweepEmailVerifiedUpdates = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_user_sweep_email_verified_updates_total",
		Help: "EmailVerification fields written by the sweeper because they disagreed with Zitadel.",
	})
)

func init() {
	metrics.Registry.MustRegister(sweepScanned, sweepMissing, sweepCreated, sweepErrors, sweepLastSuccess,
		sweepEmailVerifiedUpdates)
}

// ZitadelUserLister is the narrow slice of the pkg/zitadel API the sweeper
// needs. Eligibility is decided server-side: every human user, regardless of
// state, must have a Milo counterpart; machine users are excluded.
type ZitadelUserLister interface {
	ListHumanUsers(ctx context.Context, offset uint64, limit uint32) ([]zitadel.User, int, error)
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users/status,verbs=get;update;patch

// UserSweeper periodically ensures every Zitadel human user has a User
// resource on the core control plane. Create-only: it never deletes or
// mutates existing resources — deletion authority stays with UserController's
// finalizer flow.
type UserSweeper struct {
	Client   client.Client
	Zitadel  ZitadelUserLister
	Interval time.Duration
}

func (s *UserSweeper) Start(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("user-sweeper")
	if s.Interval <= 0 {
		log.Info("User sweep disabled (interval <= 0)")
		return nil
	}
	log.Info("Starting user sweeper", "interval", s.Interval)

	// The first sweep in an environment is the backfill — run immediately.
	if err := s.sweepOnce(ctx); err != nil {
		log.Error(err, "Sweep failed")
	}

	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.sweepOnce(ctx); err != nil {
				log.Error(err, "Sweep failed")
			}
		}
	}
}

func (s *UserSweeper) sweepOnce(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("user-sweeper")

	// One List per sweep: the manager client serves it from the shared
	// informer cache, so diffing against this set avoids a per-user Get.
	// Users created between snapshot and Create are covered by EnsureUser
	// treating AlreadyExists as success.
	var userList iammiloapiscomv1alpha1.UserList
	if err := s.Client.List(ctx, &userList); err != nil {
		sweepErrors.Inc()
		return fmt.Errorf("list existing user resources: %w", err)
	}
	existing := make(map[string]*iammiloapiscomv1alpha1.User, len(userList.Items))
	for i := range userList.Items {
		existing[userList.Items[i].Name] = &userList.Items[i]
	}

	var offset uint64
	for {
		users, raw, err := s.Zitadel.ListHumanUsers(ctx, offset, sweepPageSize)
		if err != nil {
			sweepErrors.Inc()
			return fmt.Errorf("list zitadel users (offset %d): %w", offset, err)
		}
		for i := range users {
			u := &users[i]
			sweepScanned.Inc()
			if existingUser, ok := existing[u.ID]; ok {
				// C11: reconcile the EmailVerification field. This is the backfill for
				// every account that predates the writer, and the self-heal for any
				// missed event. Diff against the User already in memory and write only
				// on mismatch (W0-C9): the sweep runs every 10 minutes and issues zero
				// Kubernetes writes per existing user today, so an unconditional write
				// would add one status update per human user per sweep.
				if emailverified.NeedsUpdate(existingUser, u.IsEmailVerified) {
					changed, err := emailverified.Set(ctx, s.Client, u.ID, u.IsEmailVerified)
					switch {
					case err != nil:
						// One user's failure must not strand the rest of the sweep:
						// the next pass reconciles it.
						sweepErrors.Inc()
						log.Error(err, "Failed to reconcile EmailVerification field", "zitadelUserId", u.ID)
					case changed:
						sweepEmailVerifiedUpdates.Inc()
					}
				}
				continue
			}
			sweepMissing.Inc()
			created, err := userprovision.EnsureUser(ctx, s.Client,
				userprovision.NewUser(u.ID, u.Email, u.GivenName, u.FamilyName))
			if err != nil {
				sweepErrors.Inc()
				return fmt.Errorf("create user %s: %w", u.ID, err)
			}
			if created {
				sweepCreated.Inc()
				log.Info("Provisioned missing User resource", "zitadelUserId", u.ID, "email", u.Email)
			}
		}
		if raw < sweepPageSize {
			break
		}
		offset += uint64(raw)
	}
	sweepLastSuccess.SetToCurrentTime()
	return nil
}
