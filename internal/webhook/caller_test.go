package webhook

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// withClientCert attaches a leaf client certificate to a request the way a verified
// mTLS handshake would. The certificate is never validated here — by the time a
// handler runs, controller-runtime has already proved the chain; what these tests
// cover is the identity check that proof does NOT perform.
func withClientCert(r *http.Request, cn string, uris ...string) *http.Request {
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			panic(err)
		}
		leaf.URIs = append(leaf.URIs, u)
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	return r
}

func bareRequest() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/v1/email/recovery", nil)
}

// S1. RequireAndVerifyClientCert proves the caller holds a certificate this CA
// signed. It says nothing about WHICH holder, so every workload issued a cert by the
// same CA can reach these endpoints. This is the check that closes that.
func TestCallerAllowed(t *testing.T) {
	tests := map[string]struct {
		allowed []string
		cn      string
		uris    []string
		hasCert bool
		want    bool
	}{
		"empty list allows any signed caller": {nil, "anything", nil, true, true},
		"blank entries are not a list":        {[]string{"", "  "}, "anything", nil, true, true},
		"listed CN passes":                    {[]string{"auth-ui"}, "auth-ui", nil, true, true},
		"listed CN among several passes":      {[]string{"other", "auth-ui"}, "auth-ui", nil, true, true},
		"unlisted CN rejected":                {[]string{"auth-ui"}, "staff-portal", nil, true, false},
		"CN match is exact, not a prefix":     {[]string{"auth-ui"}, "auth-ui-staging", nil, true, false},
		"listed URI SAN passes": {
			[]string{"spiffe://datum/ns/auth/sa/auth-ui"}, "",
			[]string{"spiffe://datum/ns/auth/sa/auth-ui"}, true, true,
		},
		"unlisted URI SAN rejected": {
			[]string{"spiffe://datum/ns/auth/sa/auth-ui"}, "",
			[]string{"spiffe://datum/ns/other/sa/thing"}, true, false,
		},
		"no client cert rejected when a list is set": {[]string{"auth-ui"}, "", nil, false, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := bareRequest()
			if tt.hasCert {
				r = withClientCert(r, tt.cn, tt.uris...)
			}

			if got := callerAllowed(r, NormalizeClientNames(tt.allowed)); got != tt.want {
				t.Fatalf("callerAllowed = %v, want %v", got, tt.want)
			}
		})
	}
}

// S4. Every mail-endpoint request is attributable, so an incident review can say
// which workload asked for a code and not merely that someone holding a CA-signed
// cert did.
func TestCallerIdentity(t *testing.T) {
	tests := map[string]struct {
		cn      string
		uris    []string
		hasCert bool
		want    string
	}{
		"common name":              {"auth-ui", nil, true, "auth-ui"},
		"URI SAN when no CN":       {"", []string{"spiffe://datum/sa/auth-ui"}, true, "spiffe://datum/sa/auth-ui"},
		"CN wins over URI SAN":     {"auth-ui", []string{"spiffe://datum/sa/x"}, true, "auth-ui"},
		"no client certificate":    {"", nil, false, "none"},
		"certificate names itself": {"", nil, true, "none"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := bareRequest()
			if tt.hasCert {
				r = withClientCert(r, tt.cn, tt.uris...)
			}

			if got := callerIdentity(r); got != tt.want {
				t.Fatalf("callerIdentity = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeClientNames(t *testing.T) {
	got := NormalizeClientNames([]string{" auth-ui ", "", "  ", "staff-portal"})

	if len(got) != 2 || got[0] != "auth-ui" || got[1] != "staff-portal" {
		t.Fatalf("NormalizeClientNames = %q, want the two trimmed names", got)
	}
	if n := len(NormalizeClientNames([]string{"", " "})); n != 0 {
		t.Fatalf("a list of blanks must normalize to empty, got %d entries", n)
	}
}

// capturedLog attaches a logr sink to the request context so a test can read the
// lines a handler emits.
func capturedLog(r *http.Request, sink *[]string) *http.Request {
	logger := funcr.New(func(prefix, args string) {
		*sink = append(*sink, prefix+" "+args)
	}, funcr.Options{})
	return r.WithContext(logf.IntoContext(r.Context(), logger))
}

func postRecoveryAs(t *testing.T, h *AccountRecoveryHandler, cn, body string, sink *[]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, AccountRecoveryEndpoint, strings.NewReader(body))
	if cn != "" {
		req = withClientCert(req, cn)
	}
	if sink != nil {
		req = capturedLog(req, sink)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAccountRecovery_UnlistedClientIs403(t *testing.T) {
	cfg := recoveryConfig()
	cfg.AllowedClientNames = []string{"auth-ui"}
	h, c, minter := newRecoveryHandlerWith(t, cfg, interceptor.Funcs{}, verifiedUser())

	rec := postRecoveryAs(t, h, "staff-portal", recoveryBody, nil)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", rec.Code, rec.Body.String())
	}
	if len(minter.calls) != 0 {
		t.Fatalf("a rejected caller must not mint a code, got %d calls", len(minter.calls))
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("expected no Email, got %d", n)
	}
}

func TestAccountRecovery_ListedClientPasses(t *testing.T) {
	cfg := recoveryConfig()
	cfg.AllowedClientNames = []string{"auth-ui"}
	h, _, _ := newRecoveryHandlerWith(t, cfg, interceptor.Funcs{}, verifiedUser())

	if rec := postRecoveryAs(t, h, "auth-ui", recoveryBody, nil); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a listed caller, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// The documented default. mTLS still proves the caller was signed by the configured
// CA; nothing pins which holder of that CA it is, which is why the server warns at
// startup and the runbook calls a list mandatory for production.
func TestAccountRecovery_EmptyAllowlistAdmitsAnySignedCaller(t *testing.T) {
	h, _, _ := newRecoveryHandlerWith(t, recoveryConfig(), interceptor.Funcs{}, verifiedUser())

	if rec := postRecoveryAs(t, h, "anything-at-all", recoveryBody, nil); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with no allowlist, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// S4: attributable either way, or an incident review can only establish that someone
// holding a CA-signed certificate asked for a code.
func TestAccountRecovery_LogsTheCallerIdentity(t *testing.T) {
	tests := map[string]struct {
		allowed []string
		cn      string
		want    string
	}{
		"accepted caller": {nil, "auth-ui", "auth-ui"},
		"rejected caller": {[]string{"auth-ui"}, "staff-portal", "staff-portal"},
		"no certificate":  {nil, "", "none"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := recoveryConfig()
			cfg.AllowedClientNames = tt.allowed
			h, _, _ := newRecoveryHandlerWith(t, cfg, interceptor.Funcs{}, verifiedUser())

			var lines []string
			postRecoveryAs(t, h, tt.cn, recoveryBody, &lines)

			var found bool
			for _, line := range lines {
				if strings.Contains(line, `"caller"`) && strings.Contains(line, tt.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no log line named caller %q; got %v", tt.want, lines)
			}
		})
	}
}

func TestEmailVerification_UnlistedClientIs403(t *testing.T) {
	cfg := verificationConfig()
	cfg.AllowedClientNames = []string{"auth-ui"}
	h, c := newHandlerWith(t, cfg, interceptor.Funcs{}, testUser())

	req := withClientCert(
		httptest.NewRequest(http.MethodPost, EmailVerificationEndpoint, strings.NewReader(goodBody)),
		"staff-portal")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", rec.Code, rec.Body.String())
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("expected no Email, got %d", n)
	}
}
