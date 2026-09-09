package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"go.miloapis.com/auth-provider-zitadel/internal/emailverified"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
)

// mockUserLister is a hand-written mock of the sweeper's Zitadel dependency
// (repo pattern: mockZitadelAPI in httpactionsserver/server_test.go).
type mockUserLister struct {
	pages [][]zitadel.User
	// raws overrides the raw server-page count per page; 0 means
	// len(pages[i]) (no rows were skipped by the human filter).
	raws  []int
	err   error
	calls int
}

func (m *mockUserLister) ListHumanUsers(_ context.Context, _ uint64, _ uint32) ([]zitadel.User, int, error) {
	if m.err != nil {
		return nil, 0, m.err
	}
	idx := m.calls
	m.calls++
	if idx >= len(m.pages) {
		return nil, 0, nil
	}
	raw := len(m.pages[idx])
	if idx < len(m.raws) && m.raws[idx] > 0 {
		raw = m.raws[idx]
	}
	return m.pages[idx], raw, nil
}

var _ = ginkgo.Describe("UserSweeper", func() {
	var (
		sctx   context.Context
		scheme *runtime.Scheme
	)

	ginkgo.BeforeEach(func() {
		sctx = context.TODO()
		scheme = runtime.NewScheme()
		gomega.Expect(iammiloapiscomv1alpha1.AddToScheme(scheme)).To(gomega.Succeed())
	})

	human := func(id, email, given, family, state string) zitadel.User {
		return zitadel.User{ID: id, Email: email, GivenName: given, FamilyName: family, State: state}
	}

	ginkgo.It("provisions every human user regardless of state, skipping existing", func() {
		k8sFake := fake.NewClientBuilder().WithScheme(scheme).Build()
		gomega.Expect(k8sFake.Create(sctx, &iammiloapiscomv1alpha1.User{
			ObjectMeta: metav1.ObjectMeta{Name: "u-existing"},
		})).To(gomega.Succeed())

		lister := &mockUserLister{pages: [][]zitadel.User{{
			human("u-existing", "a@example.com", "A", "B", "USER_STATE_ACTIVE"),
			human("u-missing", "c@example.com", "C", "D", "USER_STATE_ACTIVE"),
			human("u-inactive", "e@example.com", "E", "F", "USER_STATE_INACTIVE"),
			human("u-initial", "g@example.com", "G", "H", "USER_STATE_INITIAL"),
		}}}
		s := &UserSweeper{Client: k8sFake, Zitadel: lister}

		gomega.Expect(s.sweepOnce(sctx)).To(gomega.Succeed())

		var created iammiloapiscomv1alpha1.User
		gomega.Expect(k8sFake.Get(sctx, types.NamespacedName{Name: "u-missing"}, &created)).To(gomega.Succeed())
		gomega.Expect(created.Spec.Email).To(gomega.Equal("c@example.com"))
		gomega.Expect(created.Spec.GivenName).To(gomega.Equal("C"))

		// Milo decides the state of the user: inactive and initial Zitadel
		// users MUST get their counterpart too.
		for _, name := range []string{"u-inactive", "u-initial"} {
			gomega.Expect(k8sFake.Get(sctx, types.NamespacedName{Name: name},
				&iammiloapiscomv1alpha1.User{})).To(gomega.Succeed(), name)
		}

		var list iammiloapiscomv1alpha1.UserList
		gomega.Expect(k8sFake.List(sctx, &list)).To(gomega.Succeed())
		gomega.Expect(list.Items).To(gomega.HaveLen(4))
	})

	ginkgo.It("diffs against a single List instead of per-user Gets", func() {
		getCalls, listCalls := 0, 0
		// u-existing already agrees with Zitadel (both unverified), which is the
		// steady state after the first backfill: the EmailVerification reconcile must
		// then issue no read of its own, so the sweep stays at one List per pass
		// however many users exist (W0-C9).
		k8sFake := fake.NewClientBuilder().WithScheme(scheme).
			WithStatusSubresource(&iammiloapiscomv1alpha1.User{}).
			WithObjects(&iammiloapiscomv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "u-existing"},
				Status: iammiloapiscomv1alpha1.UserStatus{
					EmailVerification: emailverified.Desired(false),
				},
			}).
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					getCalls++
					return c.Get(ctx, key, obj, opts...)
				},
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					listCalls++
					return c.List(ctx, list, opts...)
				},
			}).Build()

		lister := &mockUserLister{pages: [][]zitadel.User{{
			human("u-existing", "a@example.com", "A", "B", "USER_STATE_ACTIVE"),
			human("u-missing", "c@example.com", "C", "D", "USER_STATE_ACTIVE"),
		}}}
		s := &UserSweeper{Client: k8sFake, Zitadel: lister}

		gomega.Expect(s.sweepOnce(sctx)).To(gomega.Succeed())
		gomega.Expect(getCalls).To(gomega.BeZero(), "sweep must not issue per-user Gets")
		gomega.Expect(listCalls).To(gomega.Equal(1), "sweep must List existing users exactly once")
	})

	ginkgo.It("paginates until a short page", func() {
		k8sFake := fake.NewClientBuilder().WithScheme(scheme).Build()
		full := make([]zitadel.User, 0, sweepPageSize)
		for i := 0; i < sweepPageSize; i++ {
			full = append(full, human(fmt.Sprintf("u-%d", i),
				fmt.Sprintf("u%d@example.com", i), "G", "F", "USER_STATE_ACTIVE"))
		}
		short := []zitadel.User{human("u-last", "last@example.com", "L", "P", "USER_STATE_ACTIVE")}
		lister := &mockUserLister{pages: [][]zitadel.User{full, short}}
		s := &UserSweeper{Client: k8sFake, Zitadel: lister}

		gomega.Expect(s.sweepOnce(sctx)).To(gomega.Succeed())
		gomega.Expect(lister.calls).To(gomega.Equal(2))

		var last iammiloapiscomv1alpha1.User
		gomega.Expect(k8sFake.Get(sctx, types.NamespacedName{Name: "u-last"}, &last)).To(gomega.Succeed())
		var list iammiloapiscomv1alpha1.UserList
		gomega.Expect(k8sFake.List(sctx, &list)).To(gomega.Succeed())
		gomega.Expect(list.Items).To(gomega.HaveLen(sweepPageSize + 1))
	})

	ginkgo.It("keeps paginating when a full server page returns fewer filtered users", func() {
		// A raw page of sweepPageSize rows where one was skipped by the
		// human filter yields len(users) < sweepPageSize; pagination must
		// advance on the raw count or later pages are never swept.
		k8sFake := fake.NewClientBuilder().WithScheme(scheme).Build()
		filtered := make([]zitadel.User, 0, sweepPageSize-1)
		for i := 0; i < sweepPageSize-1; i++ {
			filtered = append(filtered, human(fmt.Sprintf("f-%d", i),
				fmt.Sprintf("f%d@example.com", i), "G", "F", "USER_STATE_ACTIVE"))
		}
		short := []zitadel.User{human("f-after-skip", "after@example.com", "A", "S", "USER_STATE_ACTIVE")}
		lister := &mockUserLister{
			pages: [][]zitadel.User{filtered, short},
			raws:  []int{sweepPageSize, 0},
		}
		s := &UserSweeper{Client: k8sFake, Zitadel: lister}

		gomega.Expect(s.sweepOnce(sctx)).To(gomega.Succeed())
		gomega.Expect(lister.calls).To(gomega.Equal(2),
			"sweeper must fetch the next page: raw page was full even though one row was filtered")

		var after iammiloapiscomv1alpha1.User
		gomega.Expect(k8sFake.Get(sctx, types.NamespacedName{Name: "f-after-skip"}, &after)).To(gomega.Succeed())
	})

	ginkgo.It("aborts the sweep on a Zitadel error", func() {
		k8sFake := fake.NewClientBuilder().WithScheme(scheme).Build()
		s := &UserSweeper{Client: k8sFake, Zitadel: &mockUserLister{err: errors.New("boom")}}
		gomega.Expect(s.sweepOnce(sctx)).ToNot(gomega.Succeed())
	})

	ginkgo.It("does nothing when interval is zero (disabled)", func() {
		k8sFake := fake.NewClientBuilder().WithScheme(scheme).Build()
		s := &UserSweeper{Client: k8sFake, Zitadel: nil, Interval: 0}
		gomega.Expect(s.Start(sctx)).To(gomega.Succeed())
	})

	// C11: the sweep is the backfill for every existing account and the self-heal for
	// any missed event. It runs every 10 minutes and issues zero Kubernetes writes per
	// existing user today, so it must diff before writing (W0-C9).
	ginkgo.Context("EmailVerification reconcile", func() {
		verifiedHuman := func(id, email string, verified bool) zitadel.User {
			return zitadel.User{
				ID: id, Email: email, GivenName: "G", FamilyName: "F",
				State: "USER_STATE_ACTIVE", IsEmailVerified: verified,
			}
		}

		userWith := func(name string, state iammiloapiscomv1alpha1.EmailVerificationState) *iammiloapiscomv1alpha1.User {
			return &iammiloapiscomv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Status:     iammiloapiscomv1alpha1.UserStatus{EmailVerification: state},
			}
		}

		ginkgo.It("writes the field when it disagrees with Zitadel", func() {
			before := testutil.ToFloat64(sweepEmailVerifiedUpdates)
			k8sFake := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&iammiloapiscomv1alpha1.User{}).
				WithObjects(userWith("u-stale", emailverified.Desired(false))).
				Build()
			lister := &mockUserLister{pages: [][]zitadel.User{{
				verifiedHuman("u-stale", "a@example.com", true),
			}}}
			s := &UserSweeper{Client: k8sFake, Zitadel: lister}

			gomega.Expect(s.sweepOnce(sctx)).To(gomega.Succeed())

			var got iammiloapiscomv1alpha1.User
			gomega.Expect(k8sFake.Get(sctx, types.NamespacedName{Name: "u-stale"}, &got)).To(gomega.Succeed())
			gomega.Expect(emailverified.IsVerified(&got)).To(gomega.BeTrue())
			gomega.Expect(testutil.ToFloat64(sweepEmailVerifiedUpdates) - before).To(gomega.Equal(1.0))
		})

		ginkgo.It("issues no write when the field already agrees", func() {
			statusUpdates := 0
			k8sFake := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&iammiloapiscomv1alpha1.User{}).
				WithObjects(userWith("u-agrees", emailverified.Desired(true))).
				WithInterceptorFuncs(interceptor.Funcs{
					SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
						statusUpdates++
						return c.Status().Update(ctx, obj, opts...)
					},
				}).Build()
			lister := &mockUserLister{pages: [][]zitadel.User{{
				verifiedHuman("u-agrees", "a@example.com", true),
			}}}
			s := &UserSweeper{Client: k8sFake, Zitadel: lister}

			gomega.Expect(s.sweepOnce(sctx)).To(gomega.Succeed())

			gomega.Expect(statusUpdates).To(gomega.BeZero(),
				"an unconditional write would add one status update per human user every ten minutes")
		})

		ginkgo.It("backfills a user whose field is unset", func() {
			k8sFake := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&iammiloapiscomv1alpha1.User{}).
				WithObjects(userWith("u-blank", "")).
				Build()
			lister := &mockUserLister{pages: [][]zitadel.User{{
				verifiedHuman("u-blank", "a@example.com", true),
			}}}
			s := &UserSweeper{Client: k8sFake, Zitadel: lister}

			gomega.Expect(s.sweepOnce(sctx)).To(gomega.Succeed())

			var got iammiloapiscomv1alpha1.User
			gomega.Expect(k8sFake.Get(sctx, types.NamespacedName{Name: "u-blank"}, &got)).To(gomega.Succeed())
			gomega.Expect(emailverified.IsVerified(&got)).To(gomega.BeTrue())
		})

		ginkgo.It("does not abort the sweep when one field write fails", func() {
			k8sFake := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&iammiloapiscomv1alpha1.User{}).
				WithObjects(
					userWith("u-a", emailverified.Desired(false)),
					userWith("u-b", emailverified.Desired(false)),
				).
				WithInterceptorFuncs(interceptor.Funcs{
					SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
						if obj.GetName() == "u-a" {
							return errors.New("boom")
						}
						return c.Status().Update(ctx, obj, opts...)
					},
				}).Build()
			lister := &mockUserLister{pages: [][]zitadel.User{{
				verifiedHuman("u-a", "a@example.com", true),
				verifiedHuman("u-b", "b@example.com", true),
			}}}
			s := &UserSweeper{Client: k8sFake, Zitadel: lister}

			// One user's failure must not strand the rest of the sweep.
			gomega.Expect(s.sweepOnce(sctx)).To(gomega.Succeed())

			var got iammiloapiscomv1alpha1.User
			gomega.Expect(k8sFake.Get(sctx, types.NamespacedName{Name: "u-b"}, &got)).To(gomega.Succeed())
			gomega.Expect(emailverified.IsVerified(&got)).To(gomega.BeTrue())
		})
	})
})
