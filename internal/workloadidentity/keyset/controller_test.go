package keyset

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

func inlineIssuer(keys string) *iamv1alpha1.WorkloadIdentityIssuer {
	return &iamv1alpha1.WorkloadIdentityIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "idp", Generation: 3},
		Spec: iamv1alpha1.WorkloadIdentityIssuerSpec{OIDC: &iamv1alpha1.OIDCIssuer{
			IssuerURI: "https://idp.example.com",
			JWKS:      iamv1alpha1.JWKSSource{Source: iamv1alpha1.JWKSSourceInline, Inline: keys},
		}},
	}
}

func condition(t *testing.T, issuer *iamv1alpha1.WorkloadIdentityIssuer, conditionType string) metav1.Condition {
	t.Helper()
	c := meta.FindStatusCondition(issuer.Status.Conditions, conditionType)
	if c == nil {
		t.Fatalf("no %s condition", conditionType)
	}
	return *c
}

var (
	edKey = fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":"k1","x":%q}`, edX)
	ecKey = fmt.Sprintf(`{"kty":"EC","crv":"P-256","kid":"k2","x":%q,"y":%q}`, ecX, ecY)
)

func TestEvaluateAVerifiedInlineIssuer(t *testing.T) {
	issuer := inlineIssuer(`{"keys":[` + edKey + `]}`)
	now := metav1.NewTime(time.Unix(1_800_000_000, 0))
	Evaluate(issuer, now)
	s := issuer.Status
	if s.Issuer != "https://idp.example.com" || s.KeySet != `{"keys":[`+edKey+`]}` || s.KeySetGeneration != 1 ||
		s.ObservedGeneration != 3 || s.MaxTokenLifetime.Duration != time.Hour || !s.LastFetchTime.Equal(&now) {
		t.Fatalf("status = %+v", s)
	}
	if c := condition(t, issuer, "Ready"); c.Status != metav1.ConditionTrue || c.Reason != "KeySetVerified" {
		t.Fatalf("Ready = %+v", c)
	}
	if c := condition(t, issuer, "Disabled"); c.Status != metav1.ConditionFalse {
		t.Fatalf("Disabled = %+v", c)
	}

	later := metav1.NewTime(now.Add(time.Minute))
	Evaluate(issuer, later)
	if issuer.Status.KeySetGeneration != 1 || !issuer.Status.LastFetchTime.Equal(&now) {
		t.Fatalf("an unchanged key set moved the generation or fetch time: %+v", issuer.Status)
	}
	issuer.Spec.OIDC.JWKS.Inline = `{"keys":[` + edKey + `,` + ecKey + `]}`
	Evaluate(issuer, later)
	if issuer.Status.KeySetGeneration != 2 || !issuer.Status.LastFetchTime.Equal(&later) {
		t.Fatalf("a rotated key set did not move the generation: %+v", issuer.Status)
	}
}

func TestEvaluateRefusals(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(*iamv1alpha1.WorkloadIdentityIssuer)
		ready  metav1.ConditionStatus
		reason string
	}{
		{"a disabled issuer is not ready", func(i *iamv1alpha1.WorkloadIdentityIssuer) { i.Spec.Disabled = true }, metav1.ConditionFalse, "Disabled"},
		{"an unusable key is left out", func(i *iamv1alpha1.WorkloadIdentityIssuer) {
			i.Spec.OIDC.JWKS.Inline = `{"keys":[` + edKey + `,{"kty":"OKP","crv":"Ed448","kid":"k3","x":"AA"}]}`
		}, metav1.ConditionTrue, "KeysDropped"},
		{"no usable key", func(i *iamv1alpha1.WorkloadIdentityIssuer) {
			i.Spec.OIDC.JWKS.Inline = `{"keys":[{"kty":"OKP","crv":"Ed448","kid":"k3","x":"AA"}]}`
		}, metav1.ConditionFalse, "NoUsableKeys"},
		{"a key with private key material is left out", func(i *iamv1alpha1.WorkloadIdentityIssuer) {
			i.Spec.OIDC.JWKS.Inline = `{"keys":[` + edKey + `,{"kty":"EC","crv":"P-256","kid":"k3","x":"AA","y":"AA","d":"AA"}]}`
		}, metav1.ConditionTrue, "KeysDropped"},
		{"a document that is not a key set", func(i *iamv1alpha1.WorkloadIdentityIssuer) { i.Spec.OIDC.JWKS.Inline = `[]` }, metav1.ConditionFalse, "NoUsableKeys"},
		{"a key set that must be fetched", func(i *iamv1alpha1.WorkloadIdentityIssuer) {
			i.Spec.OIDC.JWKS = iamv1alpha1.JWKSSource{Source: iamv1alpha1.JWKSSourceDiscovery}
		}, metav1.ConditionFalse, "KeySourceNotSupported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := inlineIssuer(`{"keys":[` + edKey + `]}`)
			tc.edit(issuer)
			Evaluate(issuer, metav1.Now())
			if c := condition(t, issuer, "Ready"); c.Status != tc.ready || c.Reason != tc.reason {
				t.Fatalf("Ready = %s %s (%s); want %s %s", c.Status, c.Reason, c.Message, tc.ready, tc.reason)
			}
		})
	}
}

func TestEvaluateNamesAKeyWithPrivateKeyMaterial(t *testing.T) {
	// The private member is a placeholder, not key material.
	issuer := inlineIssuer(`{"keys":[` + edKey + `,{"kty":"OKP","crv":"Ed25519","kid":"k3","x":"AA","d":"c2VjcmV0"}]}`)
	Evaluate(issuer, metav1.Now())
	c := condition(t, issuer, "Ready")
	if !strings.Contains(c.Message, `kid "k3"`) || !strings.Contains(c.Message, "rotate the key") ||
		strings.Contains(c.Message, "c2VjcmV0") {
		t.Fatalf("Ready's message %q should name kid k3 and say to rotate it, without the member's value", c.Message)
	}
	if strings.Contains(issuer.Status.KeySet, "k3") {
		t.Fatalf("status.keySet %s publishes the key with private key material", issuer.Status.KeySet)
	}
}

func TestEvaluatePublishesRequiredClaims(t *testing.T) {
	issuer := inlineIssuer(`{"keys":[` + edKey + `]}`)
	Evaluate(issuer, metav1.Now())
	if issuer.Status.RequiredClaims != nil {
		t.Fatalf("status.requiredClaims = %v; want none when the spec has none", issuer.Status.RequiredClaims)
	}
	issuer.Spec.RequiredClaims = map[string]iamv1alpha1.ClaimValue{"env": "prod"}
	Evaluate(issuer, metav1.Now())
	if got := issuer.Status.RequiredClaims; len(got) != 1 || got["env"] != "prod" {
		t.Fatalf("status.requiredClaims = %v; want env=prod", got)
	}
	issuer.Spec.RequiredClaims["env"] = "dev"
	if issuer.Status.RequiredClaims["env"] != "prod" {
		t.Fatal("status.requiredClaims shares its map with the spec")
	}
}
