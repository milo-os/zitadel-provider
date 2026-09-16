package recoverymail

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	testNamespace = "milo-system"
	testUserID    = "user-1"
)

func cooldownScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := notificationv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add notification scheme: %v", err)
	}
	return s
}

// sentAgo is a recovery Email that was created ago-ago, labelled as this package
// labels the real thing.
func sentAgo(name, userID, requestedBy string, ago time.Duration) *notificationv1alpha1.Email {
	return &notificationv1alpha1.Email{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         testNamespace,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-ago)),
			Labels: map[string]string{
				LabelUser:        userID,
				LabelRequestedBy: requestedBy,
			},
		},
	}
}

func cooldownClient(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(cooldownScheme(t)).
		WithObjects(objs...).
		WithInterceptorFuncs(funcs).
		Build()
}

func tooSoon(t *testing.T, c client.Client, requestedBy string, cooldown time.Duration, maxPerHour int) bool {
	t.Helper()
	got, err := TooSoon(context.Background(), c, testNamespace, testUserID, requestedBy, cooldown, maxPerHour)
	if err != nil {
		t.Fatalf("TooSoon: unexpected error: %v", err)
	}
	return got
}

func TestTooSoon_NoPriorMailIsAllowed(t *testing.T) {
	c := cooldownClient(t, interceptor.Funcs{})

	if tooSoon(t, c, RequestedBySelf, 2*time.Minute, 5) {
		t.Fatal("a user who has never asked must not be throttled")
	}
}

// The cooldown is the control that turns "unbounded High-priority mail at an
// attacker-chosen address" into a trickle.
func TestTooSoon_RecentMailIsTooSoon(t *testing.T) {
	c := cooldownClient(t, interceptor.Funcs{}, sentAgo("a", testUserID, RequestedBySelf, 30*time.Second))

	if !tooSoon(t, c, RequestedBySelf, 2*time.Minute, 5) {
		t.Fatal("a mail 30s old must block another inside a 2m cooldown")
	}
}

func TestTooSoon_MailOlderThanTheCooldownIsAllowed(t *testing.T) {
	c := cooldownClient(t, interceptor.Funcs{}, sentAgo("a", testUserID, RequestedBySelf, 5*time.Minute))

	if tooSoon(t, c, RequestedBySelf, 2*time.Minute, 5) {
		t.Fatal("a mail past the cooldown, inside the hourly cap, must be allowed")
	}
}

// The hourly cap catches the patient attacker the cooldown alone would let through.
func TestTooSoon_HourlyCap(t *testing.T) {
	tests := map[string]struct {
		sent int
		want bool
	}{
		"under the cap": {4, false},
		"at the cap":    {5, true},
		"over the cap":  {9, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var objs []client.Object
			for i := range tt.sent {
				// All past the 2m cooldown, all inside the hour.
				objs = append(objs, sentAgo(fmt.Sprintf("a%d", i), testUserID, RequestedBySelf,
					time.Duration(5+i*5)*time.Minute))
			}
			c := cooldownClient(t, interceptor.Funcs{}, objs...)

			if got := tooSoon(t, c, RequestedBySelf, 2*time.Minute, 5); got != tt.want {
				t.Fatalf("TooSoon with %d sent this hour = %v, want %v", tt.sent, got, tt.want)
			}
		})
	}
}

// The window slides: yesterday's mail does not spend today's budget.
func TestTooSoon_IgnoresMailOlderThanAnHour(t *testing.T) {
	var objs []client.Object
	for i := range 9 {
		objs = append(objs, sentAgo(fmt.Sprintf("old%d", i), testUserID, RequestedBySelf,
			time.Duration(90+i)*time.Minute))
	}
	c := cooldownClient(t, interceptor.Funcs{}, objs...)

	if tooSoon(t, c, RequestedBySelf, 2*time.Minute, 5) {
		t.Fatal("mail older than an hour must not count against the cap")
	}
}

func TestTooSoon_ScopedToTheUser(t *testing.T) {
	c := cooldownClient(t, interceptor.Funcs{}, sentAgo("other", "user-2", RequestedBySelf, 10*time.Second))

	if tooSoon(t, c, RequestedBySelf, 2*time.Minute, 5) {
		t.Fatal("another user's recovery mail must not throttle this one")
	}
}

// A self-serve flood must not deny support the backstop that exists precisely for
// when self-serve has failed the user. Each trigger gets its own per-user budget.
func TestTooSoon_ScopedToTheTrigger(t *testing.T) {
	var objs []client.Object
	for i := range 9 {
		objs = append(objs, sentAgo(fmt.Sprintf("self%d", i), testUserID, RequestedBySelf,
			time.Duration(i)*time.Second))
	}
	c := cooldownClient(t, interceptor.Funcs{}, objs...)

	if !tooSoon(t, c, RequestedBySelf, 2*time.Minute, 5) {
		t.Fatal("the self-serve trigger must be throttled by its own flood")
	}
	if tooSoon(t, c, RequestedBySupport, 2*time.Minute, 5) {
		t.Fatal("a self-serve flood must not throttle the support backstop")
	}
}

// Zero means "no limit" for both, so an operator can turn either half off. It is
// spelled out here because 0 reading as "allow nothing" would be the other obvious
// interpretation, and the flags' help text has to agree with this one.
func TestTooSoon_ZeroDisablesEachCheck(t *testing.T) {
	var objs []client.Object
	for i := range 9 {
		objs = append(objs, sentAgo(fmt.Sprintf("a%d", i), testUserID, RequestedBySelf,
			time.Duration(i)*time.Second))
	}
	c := cooldownClient(t, interceptor.Funcs{}, objs...)

	if tooSoon(t, c, RequestedBySelf, 0, 0) {
		t.Fatal("cooldown 0 and maxPerHour 0 must impose no limit")
	}
	if !tooSoon(t, c, RequestedBySelf, 0, 5) {
		t.Fatal("maxPerHour must still apply when the cooldown is disabled")
	}
	if !tooSoon(t, c, RequestedBySelf, 2*time.Minute, 0) {
		t.Fatal("the cooldown must still apply when maxPerHour is disabled")
	}
}

// An unreadable list is not evidence that nothing was sent. The error surfaces so
// the caller can fail closed.
func TestTooSoon_ListErrorIsReturned(t *testing.T) {
	c := cooldownClient(t, interceptor.Funcs{
		List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
			return errors.New("apiserver unavailable")
		},
	})

	if _, err := TooSoon(context.Background(), c, testNamespace, testUserID,
		RequestedBySelf, 2*time.Minute, 5); err == nil {
		t.Fatal("expected the list error to surface")
	}
}
