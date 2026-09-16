package recoverymail

import (
	"net/url"
	"strings"
	"testing"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testCode = "K7QM2XD4"

func testUser() *iamv1alpha1.User {
	return &iamv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "user-1"},
		Spec: iamv1alpha1.UserSpec{
			Email: "alice@example.com", GivenName: "Alice", FamilyName: "Doe",
		},
	}
}

func selfInput() Input {
	return Input{
		User: testUser(), UserID: "user-1", CodeID: "code-id-1", Code: testCode,
		ActionURL:    "https://auth.example.test/recover/complete#code=" + testCode,
		TemplateName: "recovery-tpl", Namespace: "default", ExpiryMinutes: 60,
		RequestedBy: RequestedBySelf,
	}
}

func variables(e *notificationv1alpha1.Email) map[string]string {
	out := map[string]string{}
	for _, v := range e.Spec.Variables {
		out[v.Name] = v.Value
	}
	return out
}

func TestBuild_NameIsDeterministicAndCodeFree(t *testing.T) {
	// Arrange / Act: the same (userID, codeID) twice.
	first := Build(selfInput())
	second := Build(selfInput())

	// Assert
	if first.Name != second.Name {
		t.Errorf("name is not deterministic: %q vs %q", first.Name, second.Name)
	}
	if !strings.HasPrefix(first.Name, namePrefix) {
		t.Errorf("name = %q, want prefix %q", first.Name, namePrefix)
	}
	// An object name is not a place to put a bearer credential.
	if strings.Contains(first.Name, testCode) {
		t.Errorf("name %q contains the code", first.Name)
	}

	// A different codeID must address a different Email, or a re-issued code
	// would silently reuse the first mail.
	in := selfInput()
	in.CodeID = "code-id-2"
	if other := Build(in); other.Name == first.Name {
		t.Error("a different codeID produced the same Email name")
	}
}

func TestBuild_SelfLabelsAndNoAnnotations(t *testing.T) {
	// Act
	email := Build(selfInput())

	// Assert
	if got := email.Labels[LabelUser]; got != "user-1" {
		t.Errorf("label %s = %q, want %q", LabelUser, got, "user-1")
	}
	if got := email.Labels[LabelRequestedBy]; got != RequestedBySelf {
		t.Errorf("label %s = %q, want %q", LabelRequestedBy, got, RequestedBySelf)
	}
	// Requester and reason exist only for the support trigger.
	if _, ok := email.Annotations[AnnotationRequester]; ok {
		t.Errorf("annotation %s present on a self-serve recovery", AnnotationRequester)
	}
	if _, ok := email.Annotations[AnnotationReason]; ok {
		t.Errorf("annotation %s present on a self-serve recovery", AnnotationReason)
	}
}

func TestBuild_SupportStampsRequesterAndReason(t *testing.T) {
	// Arrange
	in := selfInput()
	in.RequestedBy = RequestedBySupport
	in.RequestedByUser = "staff-1"
	in.Reason = "user lost their laptop"

	// Act
	email := Build(in)

	// Assert
	if got := email.Labels[LabelRequestedBy]; got != RequestedBySupport {
		t.Errorf("label %s = %q, want %q", LabelRequestedBy, got, RequestedBySupport)
	}
	if got := email.Annotations[AnnotationRequester]; got != "staff-1" {
		t.Errorf("annotation %s = %q, want %q", AnnotationRequester, got, "staff-1")
	}
	if got := email.Annotations[AnnotationReason]; got != "user lost their laptop" {
		t.Errorf("annotation %s = %q, want the reason", AnnotationReason, got)
	}
}

func TestBuild_VariablesAndRecipient(t *testing.T) {
	// Act
	email := Build(selfInput())

	// Assert
	vars := variables(email)
	want := map[string]string{
		"UserName":      "Alice Doe",
		"Code":          testCode,
		"ActionUrl":     "https://auth.example.test/recover/complete#code=" + testCode,
		"ExpiryMinutes": "60",
	}
	if len(vars) != len(want) {
		t.Errorf("variables = %v, want exactly %v", vars, want)
	}
	for k, v := range want {
		if vars[k] != v {
			t.Errorf("variable %s = %q, want %q", k, vars[k], v)
		}
	}
	if email.Spec.Recipient.EmailAddress != "alice@example.com" {
		t.Errorf("recipient = %q, want the User's literal address", email.Spec.Recipient.EmailAddress)
	}
	if email.Spec.TemplateRef.Name != "recovery-tpl" {
		t.Errorf("templateRef = %q, want %q", email.Spec.TemplateRef.Name, "recovery-tpl")
	}
	if email.Spec.Priority != notificationv1alpha1.EmailPriorityHigh {
		t.Errorf("priority = %q, want High", email.Spec.Priority)
	}
	if email.Namespace != "default" {
		t.Errorf("namespace = %q, want %q", email.Namespace, "default")
	}
}

func TestBuild_UserNameFallsBackToEmail(t *testing.T) {
	in := selfInput()
	in.User = &iamv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "user-1"},
		Spec:       iamv1alpha1.UserSpec{Email: "alice@example.com"},
	}
	if got := variables(Build(in))["UserName"]; got != "alice@example.com" {
		t.Errorf("UserName = %q, want the address when there is no name", got)
	}
}

func TestBuild_ExpiryFallsBackTo60(t *testing.T) {
	for _, minutes := range []int{0, -5} {
		in := selfInput()
		in.ExpiryMinutes = minutes
		// Rendering "expires in 0 minutes" is worse than a stale number.
		if got := variables(Build(in))["ExpiryMinutes"]; got != "60" {
			t.Errorf("ExpiryMinutes for input %d = %q, want %q", minutes, got, "60")
		}
	}
}

// The identifiers stay in the query: they are not credentials, and the landing page
// needs them server-side. The code does not.
func TestActionURL_IdentifiersStayInTheQuery(t *testing.T) {
	base, err := url.Parse("https://auth.example.test/recover/complete?next=passkey")
	if err != nil {
		t.Fatal(err)
	}

	got, err := url.Parse(ActionURL(base, "user-1", "code-id-1", testCode))
	if err != nil {
		t.Fatalf("ActionURL produced an unparseable URL: %v", err)
	}

	q := got.Query()
	for k, want := range map[string]string{
		"userId": "user-1", "codeId": "code-id-1", "next": "passkey",
	} {
		if q.Get(k) != want {
			t.Errorf("query %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if got.Host != base.Host || got.Path != base.Path {
		t.Errorf("ActionURL changed the destination: %q", got.String())
	}
}

// Jose #5. The code is a bearer credential with no revocation API, so a copy in the
// landing host's access logs, its ingress/CDN, its APM or the user's history is a
// working passkey-enrollment credential for the whole expiry window. A fragment is
// never sent to a server and never appears in a Referer, which collapses that
// exposure to the browser that was handed the link.
func TestActionURL_CodeTravelsInTheFragment(t *testing.T) {
	base, err := url.Parse("https://auth.example.test/recover/complete?next=passkey")
	if err != nil {
		t.Fatal(err)
	}

	raw := ActionURL(base, "user-1", "code-id-1", testCode)
	got, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("ActionURL produced an unparseable URL: %v", err)
	}

	if _, present := got.Query()["code"]; present {
		t.Errorf("the query still carries a code key: %q", got.RawQuery)
	}
	if strings.Contains(got.RawQuery, testCode) {
		t.Errorf("the query still carries the code: %q", got.RawQuery)
	}
	if want := "code=" + testCode; got.Fragment != want {
		t.Errorf("fragment = %q, want %q", got.Fragment, want)
	}
}

// The fragment is form-urlencoded, so the landing page can read it with
// URLSearchParams and get the code back byte for byte.
func TestActionURL_FragmentIsEscaped(t *testing.T) {
	base, err := url.Parse("https://auth.example.test/recover/complete")
	if err != nil {
		t.Fatal(err)
	}
	const awkward = "a b&c=d+e#f"

	raw := ActionURL(base, "user-1", "code-id-1", awkward)

	_, fragment, found := strings.Cut(raw, "#")
	if !found {
		t.Fatalf("no fragment in %q", raw)
	}
	if strings.ContainsAny(fragment, " #") {
		t.Errorf("fragment %q is not escaped", fragment)
	}
	values, err := url.ParseQuery(fragment)
	if err != nil {
		t.Fatalf("fragment is not form-urlencoded: %v", err)
	}
	if got := values.Get("code"); got != awkward {
		t.Errorf("decoded code = %q, want %q", got, awkward)
	}
}

// The runbook's containment claim is only true if this holds, so it is asserted on
// the Email itself and not just on the helper.
func TestBuild_ActionURLQueryNeverCarriesTheCode(t *testing.T) {
	base, err := url.Parse("https://auth.example.test/recover/complete")
	if err != nil {
		t.Fatal(err)
	}
	in := selfInput()
	in.ActionURL = ActionURL(base, in.UserID, in.CodeID, in.Code)

	actionURL := variables(Build(in))["ActionUrl"]

	got, err := url.Parse(actionURL)
	if err != nil {
		t.Fatalf("ActionUrl unparseable: %v", err)
	}
	if strings.Contains(got.RawQuery, testCode) {
		t.Fatalf("the Email's ActionUrl query carries the code: %q", got.RawQuery)
	}
	if !strings.Contains(got.Fragment, testCode) {
		t.Fatalf("the Email's ActionUrl fragment lost the code: %q", got.Fragment)
	}
}
