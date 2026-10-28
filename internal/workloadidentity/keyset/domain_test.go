package keyset

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSetDomainVerifiedMatchesTheExactHost(t *testing.T) {
	verified := map[string]bool{"idp.example.com": true, "example.org": true}
	cases := []struct {
		name      string
		issuerURI string
		want      metav1.ConditionStatus
		reason    string
	}{
		{"the issuer's host is verified", "https://idp.example.com", metav1.ConditionTrue, "DomainVerified"},
		{"the host of an issuer with a path", "https://idp.example.com/tenant/v2.0", metav1.ConditionTrue, "DomainVerified"},
		{"an explicit port 443", "https://idp.example.com:443", metav1.ConditionTrue, "DomainVerified"},
		{"a host in upper case", "https://IDP.example.com", metav1.ConditionTrue, "DomainVerified"},
		{"another host", "https://login.example.com", metav1.ConditionFalse, "NoVerifiedDomain"},
		{"a subdomain of a verified domain", "https://idp.example.org", metav1.ConditionFalse, "NoVerifiedDomain"},
		{"the parent of a verified domain", "https://example.com", metav1.ConditionFalse, "NoVerifiedDomain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := inlineIssuer(`{"keys":[` + edKey + `]}`)
			issuer.Spec.OIDC.IssuerURI = tc.issuerURI
			SetDomainVerified(issuer, verified)
			if c := condition(t, issuer, "DomainVerified"); c.Status != tc.want || c.Reason != tc.reason || c.ObservedGeneration != 3 {
				t.Fatalf("DomainVerified = %+v; want %s %s", c, tc.want, tc.reason)
			}
		})
	}
	t.Run("no verified Domain at all", func(t *testing.T) {
		issuer := inlineIssuer(`{"keys":[` + edKey + `]}`)
		SetDomainVerified(issuer, map[string]bool{})
		if c := condition(t, issuer, "DomainVerified"); c.Status != metav1.ConditionFalse {
			t.Fatalf("DomainVerified = %+v; want False", c)
		}
	})
}

func domain(name, domainName string, conditions ...map[string]any) *unstructured.Unstructured {
	list := make([]any, 0, len(conditions))
	for _, c := range conditions {
		list = append(list, c)
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "networking.datumapis.com/v1alpha",
		"kind":       "Domain",
		"metadata":   map[string]any{"name": name, "namespace": "default"},
		"spec":       map[string]any{"domainName": domainName},
		"status":     map[string]any{"conditions": list},
	}}
}

func TestVerifiedDomainHostsReadsVerifiedDomainsOnly(t *testing.T) {
	domainKind := domainList.GroupVersion().WithKind("Domain")
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(domainKind, meta.RESTScopeNamespace)
	cl := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).WithRESTMapper(mapper).WithObjects(
		domain("verified", "IDP.example.com", map[string]any{"type": "Verified", "status": "True"}),
		domain("pending", "pending.example.com", map[string]any{"type": "Verified", "status": "False"}),
		domain("dns-only", "dns.example.com", map[string]any{"type": "VerifiedDNS", "status": "True"}),
		domain("no-status", "none.example.com"),
	).Build()
	hosts, err := verifiedDomainHosts(context.Background(), cl)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || !hosts["idp.example.com"] {
		t.Fatalf("verified hosts = %v; want only idp.example.com, in lower case", hosts)
	}

	// Where the Domain kind is not served, no host is verified, and that is not an error.
	cl = fake.NewClientBuilder().WithScheme(runtime.NewScheme()).WithRESTMapper(meta.NewDefaultRESTMapper(nil)).Build()
	hosts, err = verifiedDomainHosts(context.Background(), cl)
	if err != nil || len(hosts) != 0 {
		t.Fatalf("without the Domain kind: hosts %v, err %v; want none and no error", hosts, err)
	}
}
