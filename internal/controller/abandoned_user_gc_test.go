package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// A-GC. Abandoned unverified accounts.

var gcNow = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

// reaper records the ORDER of operations, because the order is the invariant:
// deleting the milo User before the Zitadel user lets UserSweeper resurrect it.
type reaper struct {
	users     []zitadel.User
	listErr   error
	deleteErr error
	calls     *[]string
	// idpLinks maps user ID to their external IdP links. Absent means none,
	// which is what a password-only signup looks like.
	idpLinks   map[string][]zitadel.IDPLink
	idpLinkErr error
	// authMethods maps user ID to the Zitadel AuthenticationMethodType names
	// backing the C9 gauge. Absent means none enrolled.
	authMethods     map[string][]string
	authMethodErr   error
	authMethodCalls int
}

func (r *reaper) ListAuthMethodTypes(_ context.Context, userID string) ([]string, error) {
	r.authMethodCalls++
	if r.authMethodErr != nil {
		return nil, r.authMethodErr
	}
	return r.authMethods[userID], nil
}

func (r *reaper) ListIDPLinks(_ context.Context, userID string) ([]zitadel.IDPLink, error) {
	if r.idpLinkErr != nil {
		return nil, r.idpLinkErr
	}
	return r.idpLinks[userID], nil
}

func (r *reaper) ListHumanUsers(context.Context, uint64, uint32) ([]zitadel.User, int, error) {
	if r.listErr != nil {
		return nil, 0, r.listErr
	}
	return r.users, len(r.users), nil
}

func (r *reaper) DeleteUser(_ context.Context, userID string) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	*r.calls = append(*r.calls, "zitadel:"+userID)
	return nil
}

// orderingClient records milo deletes into the same slice as the reaper, so one
// ordered log covers both systems.
type orderingClient struct {
	client.Client
	calls *[]string
}

func (c *orderingClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	*c.calls = append(*c.calls, "milo:"+obj.GetName())
	return c.Client.Delete(ctx, obj, opts...)
}

func newGC(t *testing.T, users []zitadel.User, dryRun bool) (*AbandonedUserGC, *[]string, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := iammiloapiscomv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	calls := &[]string{}
	objs := make([]client.Object, 0, len(users))
	for _, u := range users {
		objs = append(objs, &iammiloapiscomv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: u.ID}})
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	return &AbandonedUserGC{
		Client:    &orderingClient{Client: base, calls: calls},
		Zitadel:   &reaper{users: users, calls: calls},
		Interval:  time.Hour,
		Retention: 30 * 24 * time.Hour,
		DryRun:    dryRun,
		now:       func() time.Time { return gcNow },
	}, calls, base
}

func unverified(id string, ageDays int) zitadel.User {
	return zitadel.User{ID: id, Email: id + "@example.test", CreatedAt: gcNow.AddDate(0, 0, -ageDays)}
}

func miloUserExists(t *testing.T, c client.Client, name string) bool {
	t.Helper()
	err := c.Get(context.Background(), client.ObjectKey{Name: name}, &iammiloapiscomv1alpha1.User{})
	if apierrors.IsNotFound(err) {
		return false
	}
	if err != nil {
		t.Fatalf("get user %q: %v", name, err)
	}
	return true
}

func sweep(t *testing.T, g *AbandonedUserGC) {
	t.Helper()
	if err := g.sweepOnce(context.Background()); err != nil {
		t.Fatalf("sweepOnce: %v", err)
	}
}

// THE invariant. Zitadel first, milo second — the reverse lets UserSweeper
// recreate the User on its next tick and the two controllers fight forever.
func TestAbandonedGC_DeletesZitadelBeforeMilo(t *testing.T) {
	g, calls, _ := newGC(t, []zitadel.User{unverified("u1", 60)}, false)

	sweep(t, g)

	got := *calls
	if len(got) != 2 || got[0] != "zitadel:u1" || got[1] != "milo:u1" {
		t.Fatalf("got %v, want [zitadel:u1 milo:u1] — the Zitadel user MUST be deleted first, or user_sweep.go resurrects the milo User", got)
	}
}

func TestAbandonedGC_VerifiedAccountsSurvive(t *testing.T) {
	verified := unverified("u1", 60)
	verified.IsEmailVerified = true
	g, calls, c := newGC(t, []zitadel.User{verified}, false)

	sweep(t, g)

	if len(*calls) != 0 {
		t.Fatalf("a verified account must never be collected however old, got %v", *calls)
	}
	if !miloUserExists(t, c, "u1") {
		t.Fatal("milo User must survive")
	}
}

func TestAbandonedGC_RecentAccountsSurvive(t *testing.T) {
	g, calls, c := newGC(t, []zitadel.User{unverified("u1", 3)}, false)

	sweep(t, g)

	if len(*calls) != 0 {
		t.Fatalf("an account inside the retention window must survive, got %v", *calls)
	}
	if !miloUserExists(t, c, "u1") {
		t.Fatal("milo User must survive")
	}
}

// A zero CreatedAt means the API reported no creation date. Deleting on unknown
// age would collect accounts of unknown vintage.
func TestAbandonedGC_UnknownAgeIsSkipped(t *testing.T) {
	g, calls, c := newGC(t, []zitadel.User{{ID: "u1", Email: "u1@example.test"}}, false)

	sweep(t, g)

	if len(*calls) != 0 {
		t.Fatalf("unknown creation date must be skipped, not treated as ancient, got %v", *calls)
	}
	if !miloUserExists(t, c, "u1") {
		t.Fatal("milo User must survive")
	}
}

// Merging must not be activating: dry-run is the flag default.
func TestAbandonedGC_DryRun_DeletesNothing(t *testing.T) {
	g, calls, c := newGC(t, []zitadel.User{unverified("u1", 90)}, true)

	sweep(t, g)

	if len(*calls) != 0 {
		t.Fatalf("dry run must observe without deleting, got %v", *calls)
	}
	if !miloUserExists(t, c, "u1") {
		t.Fatal("milo User must survive a dry run")
	}
}

// Non-positive settings disable the sweep. They must never read as
// "delete everything".
func TestAbandonedGC_NonPositiveSettingsDisable(t *testing.T) {
	for name, mutate := range map[string]func(*AbandonedUserGC){
		"zero retention":     func(g *AbandonedUserGC) { g.Retention = 0 },
		"negative retention": func(g *AbandonedUserGC) { g.Retention = -time.Hour },
		"zero interval":      func(g *AbandonedUserGC) { g.Interval = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			g, calls, c := newGC(t, []zitadel.User{unverified("u1", 90)}, false)
			mutate(g)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := g.Start(ctx); err != nil {
				t.Fatalf("Start: %v", err)
			}

			if len(*calls) != 0 {
				t.Fatalf("a disabled sweep must delete nothing, got %v", *calls)
			}
			if !miloUserExists(t, c, "u1") {
				t.Fatal("milo User must survive")
			}
		})
	}
}

// If the Zitadel delete fails, the milo User must be left alone — deleting it
// would hand UserSweeper a User to recreate against a still-live Zitadel user.
func TestAbandonedGC_ZitadelDeleteFails_MiloUntouched(t *testing.T) {
	g, calls, c := newGC(t, []zitadel.User{unverified("u1", 60)}, false)
	g.Zitadel = &reaper{
		users:     []zitadel.User{unverified("u1", 60)},
		deleteErr: errors.New("zitadel unavailable"),
		calls:     calls,
	}

	sweep(t, g)

	if len(*calls) != 0 {
		t.Fatalf("no deletion should be recorded, got %v", *calls)
	}
	if !miloUserExists(t, c, "u1") {
		t.Fatal("milo User must survive a failed Zitadel delete")
	}
}

func TestAbandonedGC_ListError_IsReported(t *testing.T) {
	g, calls, _ := newGC(t, nil, false)
	g.Zitadel = &reaper{listErr: errors.New("boom"), calls: calls}

	if err := g.sweepOnce(context.Background()); err == nil {
		t.Fatal("a list failure must surface, not be swallowed")
	}
	if len(*calls) != 0 {
		t.Fatalf("nothing should be deleted, got %v", *calls)
	}
}

// The GC guard checks CreatedAt.IsZero(), so the mapping must produce the ZERO
// time for a missing creation date — not the Unix epoch.
//
// This exists because the tests above build zitadel.User directly and so never
// exercise the proto mapping. protobuf's (*Timestamp)(nil).AsTime() returns
// 1970-01-01, which is not zero, reads as ancient, and would have deleted every
// account whose creation date the API did not report.
func TestAbandonedGC_EpochIsNotTreatedAsUnknown(t *testing.T) {
	epoch := zitadel.User{ID: "u1", Email: "u1@example.test", CreatedAt: time.Unix(0, 0).UTC()}
	g, _, _ := newGC(t, nil, false)

	if !g.isAbandoned(epoch, gcNow.Add(-30*24*time.Hour)) {
		t.Fatal("an epoch CreatedAt is a real timestamp and must be collectable")
	}

	var zero zitadel.User
	zero.ID = "u2"
	if g.isAbandoned(zero, gcNow.Add(-30*24*time.Hour)) {
		t.Fatal("a ZERO CreatedAt means unknown age and must be skipped — if the mapping ever produces epoch instead of zero, this is the account that gets wrongly deleted")
	}
}

// An account that came from an external IdP is never collected. isAbandoned
// selects on Zitadel's IsEmailVerified, and nobody has confirmed what that
// reports for a Google or GitHub registration. If it says false for them, an
// unguarded sweep permanently deletes users whose provider verified their
// address years ago. The link check makes the outcome independent of that
// unknown rather than conditional on it.
func TestAbandonedGC_SkipsAccountsWithIDPLinks(t *testing.T) {
	users := []zitadel.User{unverified("social", 60), unverified("password", 60)}
	g, calls, c := newGC(t, users, false)
	g.Zitadel = &reaper{
		users:    users,
		calls:    calls,
		idpLinks: map[string][]zitadel.IDPLink{"social": {{IDPID: "google"}}},
	}

	sweep(t, g)

	for _, call := range *calls {
		if strings.Contains(call, "social") {
			t.Fatalf("collected an account with an IdP link, got %v", *calls)
		}
	}
	if !miloUserExists(t, c, "social") {
		t.Fatal("milo User for the social account must survive")
	}
	if miloUserExists(t, c, "password") {
		t.Fatal("the password-only account should still have been collected")
	}
}

// Fails closed: an unreadable link list is not evidence that there are none,
// and this loop's mistakes cannot be undone.
func TestAbandonedGC_SkipsWhenIDPLinksUnreadable(t *testing.T) {
	users := []zitadel.User{unverified("u1", 60)}
	g, calls, c := newGC(t, users, false)
	g.Zitadel = &reaper{
		users:      users,
		calls:      calls,
		idpLinkErr: errors.New("zitadel unavailable"),
	}

	sweep(t, g)

	if len(*calls) != 0 {
		t.Fatalf("must not delete when IdP links cannot be read, got %v", *calls)
	}
	if !miloUserExists(t, c, "u1") {
		t.Fatal("milo User must survive an unreadable link list")
	}
}

// C9: the stranded class — verified email, but no credential that can sign in.
// These accounts are reachable only through recovery, so they are counted, never
// collected (spec §6). Revisit trigger: 50.
func TestSweepOnce_VerifiedNoCredentialGauge(t *testing.T) {
	// Arrange: three verified users, one of each credential shape, plus an
	// unverified one that the gauge must ignore entirely.
	users := []zitadel.User{
		{ID: "u-passkey", Email: "a@example.com", IsEmailVerified: true, CreatedAt: gcNow},
		{ID: "u-password", Email: "b@example.com", IsEmailVerified: true, CreatedAt: gcNow},
		{ID: "u-otp-only", Email: "c@example.com", IsEmailVerified: true, CreatedAt: gcNow},
		{ID: "u-unverified", Email: "d@example.com", IsEmailVerified: false, CreatedAt: gcNow},
	}
	g, _, _ := newGC(t, users, true)
	r := g.Zitadel.(*reaper)
	r.authMethods = map[string][]string{
		"u-passkey":  {"AUTHENTICATION_METHOD_TYPE_PASSKEY"},
		"u-password": {"AUTHENTICATION_METHOD_TYPE_PASSWORD"},
		// otpEmail is enrolled on every Phase B account and is not a login
		// method (C2), so this user has nothing that can sign in.
		"u-otp-only": {"AUTHENTICATION_METHOD_TYPE_OTP_EMAIL"},
	}

	// Act
	if err := g.sweepOnce(context.Background()); err != nil {
		t.Fatalf("sweepOnce: %v", err)
	}

	// Assert
	if got := testutil.ToFloat64(verifiedNoCredential); got != 1 {
		t.Errorf("zitadel_provider_verified_no_credential_accounts = %v, want 1", got)
	}
	// Only verified users cost an RPC — one per verified user per GC interval.
	if r.authMethodCalls != 3 {
		t.Errorf("ListAuthMethodTypes calls = %d, want 3 (verified users only)", r.authMethodCalls)
	}
}

// An IdP link is a usable credential even with no local method enrolled.
func TestSweepOnce_IDPLinkCountsAsCredential(t *testing.T) {
	users := []zitadel.User{
		{ID: "u-idp", Email: "a@example.com", IsEmailVerified: true, CreatedAt: gcNow},
	}
	g, _, _ := newGC(t, users, true)
	r := g.Zitadel.(*reaper)
	r.authMethods = map[string][]string{"u-idp": {"AUTHENTICATION_METHOD_TYPE_IDP"}}

	if err := g.sweepOnce(context.Background()); err != nil {
		t.Fatalf("sweepOnce: %v", err)
	}

	if got := testutil.ToFloat64(verifiedNoCredential); got != 0 {
		t.Errorf("gauge = %v, want 0: an IdP link is a usable credential", got)
	}
}

// An unreadable method list is not evidence of no credential. Skip, do not count.
func TestSweepOnce_AuthMethodErrorSkipsRatherThanCounts(t *testing.T) {
	users := []zitadel.User{
		{ID: "u-verified", Email: "a@example.com", IsEmailVerified: true, CreatedAt: gcNow},
	}
	g, _, _ := newGC(t, users, true)
	r := g.Zitadel.(*reaper)
	r.authMethodErr = errors.New("zitadel unreachable")

	before := testutil.ToFloat64(abandonedErrors)
	if err := g.sweepOnce(context.Background()); err != nil {
		t.Fatalf("sweepOnce must not abort on an auth-method error: %v", err)
	}

	if got := testutil.ToFloat64(verifiedNoCredential); got != 0 {
		t.Errorf("gauge = %v, want 0: an RPC error must not be read as 'no credential'", got)
	}
	if testutil.ToFloat64(abandonedErrors)-before != 1 {
		t.Error("the skipped RPC should have incremented abandonedErrors")
	}
}
