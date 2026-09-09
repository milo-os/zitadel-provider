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

func testUser(conds ...metav1.Condition) *iamv1alpha1.User {
	return &iamv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "user-1"},
		Spec:       iamv1alpha1.UserSpec{Email: "alice@example.com"},
		Status:     iamv1alpha1.UserStatus{Conditions: conds},
	}
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

func TestSet_WritesTrueWithReason(t *testing.T) {
	// Arrange
	c := newClient(t, interceptor.Funcs{}, testUser())

	// Act
	changed, err := Set(context.Background(), c, "user-1", true)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Error("changed = false, want true for a user with no condition")
	}
	got := meta.FindStatusCondition(getUser(t, c).Status.Conditions, conditionType)
	if got == nil {
		t.Fatalf("condition %q absent after Set(true)", conditionType)
	}
	if got.Status != metav1.ConditionTrue {
		t.Errorf("status = %q, want %q", got.Status, metav1.ConditionTrue)
	}
	if got.Reason != iamv1alpha1.UserEmailVerifiedReason {
		t.Errorf("reason = %q, want %q", got.Reason, iamv1alpha1.UserEmailVerifiedReason)
	}
}

func TestSet_NoopWhenUnchanged(t *testing.T) {
	// Arrange: a user already recorded as verified.
	c := newClient(t, interceptor.Funcs{}, testUser())
	if _, err := Set(context.Background(), c, "user-1", true); err != nil {
		t.Fatalf("seed Set: %v", err)
	}
	before := getUser(t, c).ResourceVersion

	// Act
	changed, err := Set(context.Background(), c, "user-1", true)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("changed = true, want false when the stored condition already matches")
	}
	if after := getUser(t, c).ResourceVersion; after != before {
		t.Errorf("ResourceVersion moved %q -> %q; a no-op must issue no write", before, after)
	}
}

func TestSet_FlipsToFalse(t *testing.T) {
	// Arrange
	c := newClient(t, interceptor.Funcs{}, testUser())
	if _, err := Set(context.Background(), c, "user-1", true); err != nil {
		t.Fatalf("seed Set: %v", err)
	}

	// Act
	changed, err := Set(context.Background(), c, "user-1", false)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Error("changed = false, want true when flipping True -> False")
	}
	got := meta.FindStatusCondition(getUser(t, c).Status.Conditions, conditionType)
	if got == nil || got.Status != metav1.ConditionFalse {
		t.Fatalf("condition = %+v, want status False", got)
	}
	if got.Reason != iamv1alpha1.UserEmailNotVerifiedReason {
		t.Errorf("reason = %q, want %q", got.Reason, iamv1alpha1.UserEmailNotVerifiedReason)
	}
}

func TestSet_PreservesForeignConditions(t *testing.T) {
	// Arrange: a condition written by somebody else must survive our merge.
	foreign := metav1.Condition{
		Type: "Ready", Status: metav1.ConditionTrue,
		Reason: "AllGood", Message: "ready", LastTransitionTime: metav1.Now(),
	}
	c := newClient(t, interceptor.Funcs{}, testUser(foreign))

	// Act
	if _, err := Set(context.Background(), c, "user-1", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Assert
	conds := getUser(t, c).Status.Conditions
	if kept := meta.FindStatusCondition(conds, "Ready"); kept == nil {
		t.Error("foreign Ready condition was dropped")
	}
	if ours := meta.FindStatusCondition(conds, conditionType); ours == nil {
		t.Errorf("condition %q absent", conditionType)
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
	}, testUser())

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
	if !IsTrue(getUser(t, c)) {
		t.Error("condition is not True after the retry succeeded")
	}
}

func TestIsTrue(t *testing.T) {
	tests := []struct {
		name string
		user *iamv1alpha1.User
		want bool
	}{
		{"nil user", nil, false},
		{"no conditions", testUser(), false},
		{"condition False", testUser(Desired(false)), false},
		{"condition True", testUser(Desired(true)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTrue(tt.user); got != tt.want {
				t.Errorf("IsTrue() = %v, want %v", got, tt.want)
			}
		})
	}
}
