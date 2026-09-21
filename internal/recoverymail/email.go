// Package recoverymail builds the account-recovery notification Email.
//
// It is shared by the two triggers that can send one — the /v1/email/recovery webhook
// (self-serve) and the PasskeyRegistrationLink REST create (support) — so both produce
// the same mail and the same audit record. The Email is that record: the identity
// apiserver is virtual and persists nothing, so who asked and why are stamped here.
//
// The registration code is a bearer credential. It reaches exactly two fields — the
// "Code" variable, and the fragment of the "ActionUrl" variable, which browsers never
// send to a server. It is never part of the object name, a label, an annotation, a log
// field, an error message, or the query string of that URL.
package recoverymail

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The closed vocabulary for who triggered the recovery. It selects the template at the
// call site and is recorded on the Email; a request cannot supply anything else.
const (
	RequestedBySelf    = "self"
	RequestedBySupport = "support"
)

// Labels and annotations staff-portal lists the sent links by.
const (
	LabelUser           = "identity.miloapis.com/user"
	LabelRequestedBy    = "identity.miloapis.com/recovery-requested-by"
	AnnotationRequester = "identity.miloapis.com/recovery-requester"
	AnnotationReason    = "identity.miloapis.com/recovery-reason"
)

// namePrefix identifies these Emails; the REST resource derives its own object name
// from the same suffix so the two can be correlated.
const namePrefix = "account-recovery-"

// defaultExpiryMinutes is the fallback when the operator supplies no lifetime.
// Rendering "expires in 0 minutes" to a user is worse than a stale number.
const defaultExpiryMinutes = 60

// Input is everything Build needs. RequestedByUser and Reason are used only when
// RequestedBy is RequestedBySupport.
type Input struct {
	User          *iamv1alpha1.User
	UserID        string
	CodeID        string
	Code          string
	ActionURL     string
	TemplateName  string
	Namespace     string
	ExpiryMinutes int

	RequestedBy     string
	RequestedByUser string
	Reason          string
}

// Build assembles the recovery Email.
//
// The name is derived from userID+codeID so a retried request addresses the same
// object and sends one mail; it is hashed rather than composed because a code id is
// still an identifier we would rather not publish in an object name.
func Build(in Input) *notificationv1alpha1.Email {
	displayName := strings.TrimSpace(in.User.Spec.GivenName + " " + in.User.Spec.FamilyName)
	if displayName == "" {
		displayName = in.User.Spec.Email
	}

	expiryMinutes := in.ExpiryMinutes
	if expiryMinutes <= 0 {
		expiryMinutes = defaultExpiryMinutes
	}

	sum := sha256.Sum256([]byte(in.UserID + ":" + in.CodeID))
	name := namePrefix + hex.EncodeToString(sum[:])[:16]

	email := &notificationv1alpha1.Email{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Email",
			APIVersion: "notification.miloapis.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: in.Namespace,
			Labels: map[string]string{
				LabelUser:        in.UserID,
				LabelRequestedBy: in.RequestedBy,
			},
		},
		Spec: notificationv1alpha1.EmailSpec{
			TemplateRef: notificationv1alpha1.TemplateReference{Name: in.TemplateName},
			// Literal address: the caller has already read the User, so a UserRef
			// would only have the pipeline resolve the same record again.
			Recipient: notificationv1alpha1.EmailRecipient{EmailAddress: in.User.Spec.Email},
			Variables: []notificationv1alpha1.EmailVariable{
				{Name: "UserName", Value: displayName},
				{Name: "Code", Value: in.Code},
				{Name: "ActionUrl", Value: in.ActionURL},
				{Name: "ExpiryMinutes", Value: strconv.Itoa(expiryMinutes)},
			},
			Priority: notificationv1alpha1.EmailPriorityHigh,
		},
	}

	// Support is the only trigger with a human behind it to record.
	if in.RequestedBy == RequestedBySupport {
		email.Annotations = map[string]string{
			AnnotationRequester: in.RequestedByUser,
			AnnotationReason:    in.Reason,
		}
	}

	return email
}

// ActionURL adds the values the recovery ceremony needs to an already-validated base
// URL. It takes the parsed URL rather than a raw string so the link cannot be built
// from a destination the caller's allowlist did not approve.
//
// userId and codeId are identifiers, not credentials, and stay in the query where the
// landing page can read them server-side. The code goes in the FRAGMENT, which
// browsers never send to a server: not in the request line, not in a Referer. In the
// query it would have been written verbatim into the landing host's access logs, its
// ingress or CDN logs and its APM — systems retained longer, replicated wider and
// access-controlled far more loosely than anything meant to hold secrets, and often
// shipped to a third party. Since Zitadel's v2 API cannot revoke an issued
// registration code, every one of those copies is a working passkey-enrollment
// credential until it expires. The fragment collapses that back to the browser the
// user opened the link in.
//
// The fragment is form-urlencoded so the landing page can read it with
// URLSearchParams and get the code back byte for byte. It is appended rather than
// assigned to u.Fragment because url.URL re-escapes a fragment under rules that leave
// "+" alone, which URLSearchParams would then decode as a space.
func ActionURL(base *url.URL, userID, codeID, code string) string {
	u := *base
	q := u.Query()
	q.Set("userId", userID)
	q.Set("codeId", codeID)
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String() + "#" + url.Values{"code": {code}}.Encode()
}
