package emailverified

import (
	"context"
	"errors"
	"testing"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := iamv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func testUser(status iamv1alpha1.UserStatus) *iamv1alpha1.User {
	return &iamv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "user-1"},
		Spec:       iamv1alpha1.UserSpec{Email: "alice@example.com"},
		Status:     status,
	}
}

func userIn(state iamv1alpha1.EmailVerificationState) *iamv1alpha1.User {
	return testUser(iamv1alpha1.UserStatus{EmailVerification: state})
}

func newClient(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithStatusSubresource(&iamv1alpha1.User{}).
		WithObjects(objs...).
		WithInterceptorFuncs(funcs).
		Build()
}

func getUser(t *testing.T, c client.Client) *iamv1alpha1.User {
	t.Helper()
	out := &iamv1alpha1.User{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "user-1"}, out); err != nil {
		t.Fatalf("re-Get: %v", err)
	}
	return out
}

func TestSet_WritesVerified(t *testing.T) {
	// Arrange
	c := newClient(t, interceptor.Funcs{}, userIn(""))

	// Act
	changed, err := Set(context.Background(), c, "user-1", true)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Error("changed = false, want true for a user with an unset field")
	}
	if got := getUser(t, c).Status.EmailVerification; got != iamv1alpha1.EmailVerificationStateVerified {
		t.Errorf("emailVerification = %q, want %q", got, iamv1alpha1.EmailVerificationStateVerified)
	}
}

func TestSet_NoopWhenUnchanged(t *testing.T) {
	// Arrange: a user already recorded as verified.
	c := newClient(t, interceptor.Funcs{}, userIn(iamv1alpha1.EmailVerificationStateVerified))
	before := getUser(t, c).ResourceVersion

	// Act
	changed, err := Set(context.Background(), c, "user-1", true)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("changed = true, want false when the stored field already matches")
	}
	if after := getUser(t, c).ResourceVersion; after != before {
		t.Errorf("ResourceVersion moved %q -> %q; a no-op must issue no write", before, after)
	}
}

func TestSet_FlipsToUnverified(t *testing.T) {
	// Arrange
	c := newClient(t, interceptor.Funcs{}, userIn(iamv1alpha1.EmailVerificationStateVerified))

	// Act
	changed, err := Set(context.Background(), c, "user-1", false)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Error("changed = false, want true when flipping Verified -> Unverified")
	}
	if got := getUser(t, c).Status.EmailVerification; got != iamv1alpha1.EmailVerificationStateUnverified {
		t.Errorf("emailVerification = %q, want %q", got, iamv1alpha1.EmailVerificationStateUnverified)
	}
}

// Status().Update writes the whole status, so the read-modify-write must carry every
// field somebody else owns back out untouched.
func TestSet_PreservesOtherStatusFields(t *testing.T) {
	// Arrange
	c := newClient(t, interceptor.Funcs{}, testUser(iamv1alpha1.UserStatus{
		State:          iamv1alpha1.UserStateActive,
		PlatformAccess: iamv1alpha1.PlatformAccessStateApproved,
		Conditions: []metav1.Condition{{
			Type: "Ready", Status: metav1.ConditionTrue,
			Reason: "AllGood", Message: "ready", LastTransitionTime: metav1.Now(),
		}},
	}))

	// Act
	if _, err := Set(context.Background(), c, "user-1", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Assert
	got := getUser(t, c)
	if got.Status.EmailVerification != iamv1alpha1.EmailVerificationStateVerified {
		t.Errorf("emailVerification = %q, want %q", got.Status.EmailVerification, iamv1alpha1.EmailVerificationStateVerified)
	}
	if got.Status.State != iamv1alpha1.UserStateActive {
		t.Errorf("state = %q, want %q", got.Status.State, iamv1alpha1.UserStateActive)
	}
	if got.Status.PlatformAccess != iamv1alpha1.PlatformAccessStateApproved {
		t.Errorf("platformAccess = %q, want %q", got.Status.PlatformAccess, iamv1alpha1.PlatformAccessStateApproved)
	}
	if meta.FindStatusCondition(got.Status.Conditions, "Ready") == nil {
		t.Error("foreign Ready condition was dropped")
	}
}

func TestSet_RetriesOnConflict(t *testing.T) {
	// Arrange: the first status update loses the optimistic-lock race.
	var updates int
	c := newClient(t, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			updates++
			if updates == 1 {
				return apierrors.NewConflict(
					schema.GroupResource{Group: iamv1alpha1.SchemeGroupVersion.Group, Resource: "users"},
					obj.GetName(), errors.New("the object has been modified"),
				)
			}
			return cl.Status().Update(ctx, obj, opts...)
		},
	}, userIn(""))

	// Act
	changed, err := Set(context.Background(), c, "user-1", true)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Error("changed = false, want true after a successful retry")
	}
	if updates != 2 {
		t.Errorf("status updates = %d, want 2 (one conflict, one success)", updates)
	}
	if !IsVerified(getUser(t, c)) {
		t.Error("field is not Verified after the retry succeeded")
	}
}

func TestIsVerified(t *testing.T) {
	tests := []struct {
		name string
		user *iamv1alpha1.User
		want bool
	}{
		{"nil user", nil, false},
		{"not synced yet", userIn(""), false},
		{"Unverified", userIn(iamv1alpha1.EmailVerificationStateUnverified), false},
		{"Verified", userIn(iamv1alpha1.EmailVerificationStateVerified), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsVerified(tt.user); got != tt.want {
				t.Errorf("IsVerified() = %v, want %v", got, tt.want)
			}
		})
	}
}
