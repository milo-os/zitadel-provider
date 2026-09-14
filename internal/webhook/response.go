package webhook

import (
	"strconv"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Keys stamped into TokenReview's status.user.extra, read by milo's
// ValidatingAdmissionPolicies off the authenticated userInfo.
const (
	registrationApprovalExtraKey = "iam.miloapis.com/registrationApproval"
	emailVerifiedExtraKey        = "iam.miloapis.com/emailVerified"
)

func Denied(reason string) Response {
	return authenticationResponse(false, "", "", reason, iammiloapiscomv1alpha1.PlatformAccessStateRejected, nil)
}

func Errored(err error) Response {
	return authenticationResponse(false, "", "", err.Error(), iammiloapiscomv1alpha1.PlatformAccessStateRejected, nil)
}

// Allowed builds an authenticated TokenReview response for the given identity.
//
// Pass a non-nil emailVerified for human identities and nil for machines. Never
// pass nil to mean "could not determine" — an absent key admits.
func Allowed(username, uid string, emailVerified *bool) Response {
	return authenticationResponse(true, username, uid, "", iammiloapiscomv1alpha1.PlatformAccessStateApproved, emailVerified)
}

func authenticationResponse(authenticated bool, username, uid, evaluationError string, state iammiloapiscomv1alpha1.PlatformAccessState, emailVerified *bool) Response {
	extra := map[string]authenticationv1.ExtraValue{
		registrationApprovalExtraKey: {string(state)},
	}

	// Presence is the signal: milo's policies admit when the key is absent, so
	// absence must mean "machine identity", never "state unknown". Machines carry
	// no email claim and are admitted by absence; humans always get the key, set
	// to "true" or "false".
	//
	// Both an unverified human and one whose email_verified claim Zitadel omitted
	// arrive here as false (oidc.IntrospectionResponse tags it omitempty).
	// Collapsing that to false gates every human loudly; collapsing it to an
	// absent key would admit them all silently.
	if emailVerified != nil {
		extra[emailVerifiedExtraKey] = authenticationv1.ExtraValue{strconv.FormatBool(*emailVerified)}
	}

	return Response{
		TokenReview: authenticationv1.TokenReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "TokenReview",
				APIVersion: authenticationv1.SchemeGroupVersion.String(),
			},
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: authenticated,
				User: authenticationv1.UserInfo{
					Username: username,
					UID:      uid,
					Extra:    extra,
				},
				Error: evaluationError,
			},
		},
	}
}
