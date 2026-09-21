package webhook

import (
	"crypto/x509"
	"net/http"
	"strings"
)

// unknownCaller is the identity reported for a request with no usable client
// certificate. It is a literal rather than an empty string so it cannot be mistaken
// for a missing log field.
const unknownCaller = "none"

// NormalizeClientNames trims and drops blank entries from the configured allowlist.
//
// It exists because an unset env var reaches the binary as --flag= rather than as an
// absent flag, which a naive length check would read as a one-entry allowlist that
// matches nothing — turning the documented default into a 403 for every caller.
// Normalizing once at startup keeps that decision in one place.
func NormalizeClientNames(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, name := range raw {
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// callerAllowed reports whether the request's client certificate names one of the
// allowed identities.
//
// controller-runtime's RequireAndVerifyClientCert proves only that the caller holds a
// certificate the configured CA signed — it never inspects who the certificate says
// they are. In a cluster where one CA issues certs to many workloads, that makes the
// mail endpoints reachable by every one of them. This is the check that turns "signed
// by our CA" into "is the caller we meant".
//
// An empty list allows any signed caller, which is the documented default and the
// reason runWebhookServer logs a startup warning when it is left that way. Callers
// pass the list through NormalizeClientNames first.
func callerAllowed(r *http.Request, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	leaf := leafCert(r)
	if leaf == nil {
		return false
	}
	for _, name := range allowed {
		// Exact match only: a prefix or suffix rule would admit "auth-ui-staging"
		// wherever "auth-ui" was meant.
		if leaf.Subject.CommonName == name {
			return true
		}
		for _, uri := range leaf.URIs {
			if uri.String() == name {
				return true
			}
		}
	}
	return false
}

// callerIdentity names the client behind a request, for the log line every
// mail-endpoint request emits. Without it an incident review can only establish that
// someone holding a CA-signed certificate asked for a code.
//
// CN first, then the first URI SAN, which is where SPIFFE-style identities live.
func callerIdentity(r *http.Request) string {
	leaf := leafCert(r)
	if leaf == nil {
		return unknownCaller
	}
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName
	}
	if len(leaf.URIs) > 0 {
		return leaf.URIs[0].String()
	}
	return unknownCaller
}

func leafCert(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}
