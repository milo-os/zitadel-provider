package passkeyregistrationlinks

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.miloapis.com/auth-provider-zitadel/internal/emailverified"
	"go.miloapis.com/auth-provider-zitadel/internal/recoverymail"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	milov1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	authzv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const theCode = "K7QM2XD4"

// fakeZitadelAPI stubs zitadel.API. Only CreatePasskeyRegistrationLink is implemented;
// any other call panics via the embedded nil interface — this resource calls nothing else.
type fakeZitadelAPI struct {
	zitadel.API
	calls int
	link  func(ctx context.Context, userID string) (string, string, error)
}

func (f *fakeZitadelAPI) CreatePasskeyRegistrationLink(ctx context.Context, userID string) (string, string, error) {
	f.calls++
	if f.link != nil {
		return f.link(ctx, userID)
	}
	return "code-id-1", theCode, nil
}

// fakeSAR records the review it was asked for so a test can assert the attributes.
type fakeSAR struct {
	allowed bool
	err     error
	got     *authzv1.SubjectAccessReview
}

func (f *fakeSAR) Create(_ context.Context, sar *authzv1.SubjectAccessReview, _ metav1.CreateOptions) (*authzv1.SubjectAccessReview, error) {
	f.got = sar
	if f.err != nil {
		return nil, f.err
	}
	out := sar.DeepCopy()
	out.Status.Allowed = f.allowed
	return out, nil
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		iamv1alpha1.AddToScheme, notificationv1alpha1.AddToScheme,
	} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func verifiedUser() *iamv1alpha1.User {
	return &iamv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "user-1", UID: "uid-1"},
		Spec: iamv1alpha1.UserSpec{
			Email: "person@example.test", GivenName: "Ada", FamilyName: "Lovelace",
		},
		Status: iamv1alpha1.UserStatus{Conditions: []metav1.Condition{withNow(emailverified.Desired(true))}},
	}
}

func unverifiedUser() *iamv1alpha1.User {
	u := verifiedUser()
	u.Status.Conditions = []metav1.Condition{withNow(emailverified.Desired(false))}
	return u
}

func withNow(c metav1.Condition) metav1.Condition {
	c.LastTransitionTime = metav1.Now()
	return c
}

type harness struct {
	rest *REST
	z    *fakeZitadelAPI
	sar  *fakeSAR
	milo client.Client
}

func newREST(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) *harness {
	t.Helper()
	z := &fakeZitadelAPI{}
	sar := &fakeSAR{allowed: true}
	milo := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		WithInterceptorFuncs(funcs).
		Build()

	r, err := New(Options{
		Z: z, Milo: milo, MiloSAR: sar, Enabled: true,
		SupportTemplateName:   "recovery-support-tpl",
		NotificationNamespace: "default",
		CompleteURL:           "https://auth.example.test/recover/complete",
		ExpiryMinutes:         60,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &harness{rest: r, z: z, sar: sar, milo: milo}
}

func callerCtx() context.Context {
	return request.WithUser(context.Background(), &user.DefaultInfo{Name: "staff-1", UID: "staff-uid"})
}

func link() *milov1alpha1.PasskeyRegistrationLink {
	return &milov1alpha1.PasskeyRegistrationLink{
		Spec: milov1alpha1.PasskeyRegistrationLinkSpec{
			UserRef:     milov1alpha1.PasskeyRegistrationLinkUserReference{Name: "user-1"},
			RequestedBy: "staff-1",
			Reason:      "ticket-42: user lost their laptop",
		},
	}
}

func create(t *testing.T, h *harness, obj *milov1alpha1.PasskeyRegistrationLink) (runtime.Object, error) {
	t.Helper()
	return h.rest.Create(callerCtx(), obj, nil, &metav1.CreateOptions{})
}

func emails(t *testing.T, c client.Client) []notificationv1alpha1.Email {
	t.Helper()
	var list notificationv1alpha1.EmailList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	return list.Items
}

// The infra-owned switch: the role can ship dormant while the flag is off.
func TestCreate_DisabledIs503(t *testing.T) {
	h := newREST(t, interceptor.Funcs{}, verifiedUser())
	h.rest.Enabled = false

	_, err := create(t, h, link())

	if !apierrors.IsServiceUnavailable(err) {
		t.Fatalf("expected 503 ServiceUnavailable, got %v", err)
	}
	if h.z.calls != 0 {
		t.Error("no code may be minted while the flag is off")
	}
	if n := len(emails(t, h.milo)); n != 0 {
		t.Errorf("expected no Email, got %d", n)
	}
}

func TestCreate_RequiredFields(t *testing.T) {
	for name, mutate := range map[string]func(*milov1alpha1.PasskeyRegistrationLink){
		"no userRef.name": func(l *milov1alpha1.PasskeyRegistrationLink) { l.Spec.UserRef.Name = "" },
		"no reason":       func(l *milov1alpha1.PasskeyRegistrationLink) { l.Spec.Reason = "" },
		"blank reason":    func(l *milov1alpha1.PasskeyRegistrationLink) { l.Spec.Reason = "   " },
	} {
		t.Run(name, func(t *testing.T) {
			h := newREST(t, interceptor.Funcs{}, verifiedUser())
			l := link()
			mutate(l)

			_, err := create(t, h, l)

			if !apierrors.IsBadRequest(err) {
				t.Fatalf("expected 400 BadRequest, got %v", err)
			}
			if h.z.calls != 0 {
				t.Error("a rejected request must not mint a code")
			}
		})
	}
}

// requestedBy is the audit record; a caller may not attribute a link to someone else.
func TestCreate_RequestedByMustBeTheCaller(t *testing.T) {
	h := newREST(t, interceptor.Funcs{}, verifiedUser())
	l := link()
	l.Spec.RequestedBy = "someone-else"

	_, err := create(t, h, l)

	if !apierrors.IsBadRequest(err) {
		t.Fatalf("expected 400 BadRequest, got %v", err)
	}
	if h.z.calls != 0 {
		t.Error("a rejected request must not mint a code")
	}
}

func TestCreate_SARDeniedIs403(t *testing.T) {
	h := newREST(t, interceptor.Funcs{}, verifiedUser())
	h.sar.allowed = false

	_, err := create(t, h, link())

	if !apierrors.IsForbidden(err) {
		t.Fatalf("expected 403 Forbidden, got %v", err)
	}
	if h.z.calls != 0 {
		t.Error("a denied caller must not mint a code")
	}
}

// The SAR is the whole authorization story: milo is the policy decision point.
func TestCreate_SARAsksMiloForTheRightThing(t *testing.T) {
	h := newREST(t, interceptor.Funcs{}, verifiedUser())

	if _, err := create(t, h, link()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.sar.got == nil {
		t.Fatal("no SubjectAccessReview was issued")
	}
	attrs := h.sar.got.Spec.ResourceAttributes
	if attrs == nil {
		t.Fatal("SAR carried no ResourceAttributes")
	}
	if attrs.Group != "identity.miloapis.com" {
		t.Errorf("SAR group = %q", attrs.Group)
	}
	if attrs.Resource != "passkeyregistrationlinks" {
		t.Errorf("SAR resource = %q", attrs.Resource)
	}
	if attrs.Verb != "create" {
		t.Errorf("SAR verb = %q", attrs.Verb)
	}
	if attrs.Name != "user-1" {
		t.Errorf("SAR name = %q, want the target user", attrs.Name)
	}
	if h.sar.got.Spec.User != "staff-1" {
		t.Errorf("SAR user = %q, want the caller", h.sar.got.Spec.User)
	}
	// The parent context milo's OpenFGA authorizer reads.
	extra := h.sar.got.Spec.Extra
	if got := extra["iam.miloapis.com/parent-type"]; len(got) != 1 || got[0] != "User" {
		t.Errorf("parent-type extra = %v, want [User]", got)
	}
	if got := extra["iam.miloapis.com/parent-name"]; len(got) != 1 || got[0] != "user-1" {
		t.Errorf("parent-name extra = %v, want [user-1]", got)
	}
}

// Support is a trusted caller, so this is a clear rejection rather than a silent one.
func TestCreate_UnverifiedUserIsRejected(t *testing.T) {
	for name, u := range map[string]*iamv1alpha1.User{
		"condition False":   unverifiedUser(),
		"condition missing": {ObjectMeta: metav1.ObjectMeta{Name: "user-1", UID: "uid-1"}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newREST(t, interceptor.Funcs{}, u)

			_, err := create(t, h, link())

			if !apierrors.IsBadRequest(err) {
				t.Fatalf("expected 400 BadRequest, got %v", err)
			}
			if !strings.Contains(err.Error(), "not verified") {
				t.Errorf("error should say the address is not verified, got: %v", err)
			}
			if h.z.calls != 0 {
				t.Error("no code may be minted for an unverified address")
			}
			if n := len(emails(t, h.milo)); n != 0 {
				t.Errorf("expected no Email, got %d", n)
			}
		})
	}
}

func TestCreate_UnknownUserIs404(t *testing.T) {
	h := newREST(t, interceptor.Funcs{})

	_, err := create(t, h, link())

	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected 404 NotFound, got %v", err)
	}
	if h.z.calls != 0 {
		t.Error("no code may be minted for a user that does not exist")
	}
}

func TestCreate_HappyPath(t *testing.T) {
	h := newREST(t, interceptor.Funcs{}, verifiedUser())
	before := time.Now()

	out, err := create(t, h, link())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// One code, one mail.
	if h.z.calls != 1 {
		t.Errorf("CreatePasskeyRegistrationLink calls = %d, want 1", h.z.calls)
	}
	list := emails(t, h.milo)
	if len(list) != 1 {
		t.Fatalf("expected one Email, got %d", len(list))
	}
	e := list[0]

	if e.Spec.TemplateRef.Name != "recovery-support-tpl" {
		t.Errorf("templateRef = %q, want the support template", e.Spec.TemplateRef.Name)
	}
	if got := e.Labels[recoverymail.LabelRequestedBy]; got != recoverymail.RequestedBySupport {
		t.Errorf("requested-by label = %q, want %q", got, recoverymail.RequestedBySupport)
	}
	if got := e.Labels[recoverymail.LabelUser]; got != "user-1" {
		t.Errorf("user label = %q", got)
	}
	if got := e.Annotations[recoverymail.AnnotationRequester]; got != "staff-1" {
		t.Errorf("requester annotation = %q, want the caller", got)
	}
	if got := e.Annotations[recoverymail.AnnotationReason]; got != "ticket-42: user lost their laptop" {
		t.Errorf("reason annotation = %q", got)
	}
	if e.Spec.Recipient.EmailAddress != "person@example.test" {
		t.Errorf("recipient = %q, want the verified address on file", e.Spec.Recipient.EmailAddress)
	}

	got, ok := out.(*milov1alpha1.PasskeyRegistrationLink)
	if !ok {
		t.Fatalf("Create returned %T, want *PasskeyRegistrationLink", out)
	}
	if !strings.HasPrefix(got.Name, "passkey-recovery-") {
		t.Errorf("name = %q, want the passkey-recovery- prefix", got.Name)
	}
	if got.Status.UserUID != "uid-1" {
		t.Errorf("status.userUID = %q, want uid-1", got.Status.UserUID)
	}
	if got.Status.EmailName != e.Name {
		t.Errorf("status.emailName = %q, want %q", got.Status.EmailName, e.Name)
	}
	if got.Status.ExpiresAt == nil {
		t.Fatal("status.expiresAt is nil")
	}
	wantLo, wantHi := before.Add(59*time.Minute), time.Now().Add(61*time.Minute)
	if got.Status.ExpiresAt.Time.Before(wantLo) || got.Status.ExpiresAt.Time.After(wantHi) {
		t.Errorf("status.expiresAt = %v, want ~now+60m", got.Status.ExpiresAt.Time)
	}
}

// The code is a bearer credential: it reaches the Email's Variables and nothing else.
func TestCreate_CodeNeverLeavesTheEmail(t *testing.T) {
	h := newREST(t, interceptor.Funcs{}, verifiedUser())

	out, err := create(t, h, link())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := out.(*milov1alpha1.PasskeyRegistrationLink)
	if strings.Contains(got.Name, theCode) {
		t.Errorf("returned name %q contains the code", got.Name)
	}
	if strings.Contains(got.Status.EmailName, theCode) {
		t.Errorf("status.emailName %q contains the code", got.Status.EmailName)
	}
	if strings.Contains(got.Status.UserUID+got.Spec.Reason+got.Spec.RequestedBy, theCode) {
		t.Error("the code leaked into the returned object")
	}

	e := emails(t, h.milo)[0]
	if strings.Contains(e.Name, theCode) {
		t.Errorf("Email name %q contains the code", e.Name)
	}
	var codeVar string
	for _, v := range e.Spec.Variables {
		if v.Name == "Code" {
			codeVar = v.Value
		}
	}
	if codeVar != theCode {
		t.Errorf("Code variable = %q, want the code to still reach the template", codeVar)
	}
}

// An apiserver rejection can quote the object it rejected, and that object carries
// the code. The returned error must not become a channel for it.
func TestCreate_EmailCreateFailureDoesNotEchoCode(t *testing.T) {
	h := newREST(t, interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			return errors.New(`admission denied for Email with Variables [{Code ` + theCode + `}]`)
		},
	}, verifiedUser())

	_, err := create(t, h, link())

	if err == nil {
		t.Fatal("expected an error when the Email create fails")
	}
	if strings.Contains(err.Error(), theCode) {
		t.Fatalf("error echoed the recovery code: %v", err)
	}
}

func TestNew_RejectsMalformedCompleteURL(t *testing.T) {
	_, err := New(Options{
		Z: &fakeZitadelAPI{}, Enabled: true, CompleteURL: "://not a url",
	})
	if err == nil {
		t.Fatal("expected New to reject a malformed --account-recovery-complete-url")
	}
}

func TestRESTInterface(t *testing.T) {
	h := newREST(t, interceptor.Funcs{})
	if h.rest.NamespaceScoped() {
		t.Error("NamespaceScoped() = true, want false")
	}
	if _, ok := h.rest.New().(*milov1alpha1.PasskeyRegistrationLink); !ok {
		t.Error("New() returned the wrong type")
	}
	if got := h.rest.GetSingularName(); got != "passkeyregistrationlink" {
		t.Errorf("GetSingularName() = %q", got)
	}
	h.rest.Destroy()
}
