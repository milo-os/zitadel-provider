package token

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signedToken builds a JWT carrying claims. The signing key is irrelevant to
// what is under test — Inspect never verifies — but a real signature keeps the
// fixture a well-formed JWS rather than a hand-assembled string.
func signedToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-key"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func withFrozenClock(t *testing.T, now time.Time) {
	t.Helper()

	prev := nowFunc
	nowFunc = func() time.Time { return now }
	t.Cleanup(func() { nowFunc = prev })
}

func TestInspectExpiredJWT(t *testing.T) {
	now := time.Date(2026, 8, 24, 19, 11, 0, 0, time.UTC)
	withFrozenClock(t, now)

	tok := signedToken(t, jwt.MapClaims{
		"sub":       "387723717020506409",
		"iss":       "https://auth.datum.net",
		"aud":       []string{"cloud-portal"},
		"client_id": "portal-client",
		"iat":       now.Add(-30 * time.Minute).Unix(),
		"exp":       now.Add(-90 * time.Second).Unix(),
	})

	d := Inspect(tok)

	if d.Format != "jwt" {
		t.Errorf("Format = %q, want %q", d.Format, "jwt")
	}
	if d.Subject != "387723717020506409" {
		t.Errorf("Subject = %q", d.Subject)
	}
	if d.Issuer != "https://auth.datum.net" {
		t.Errorf("Issuer = %q", d.Issuer)
	}
	if d.ClientID != "portal-client" {
		t.Errorf("ClientID = %q", d.ClientID)
	}
	if len(d.Audience) != 1 || d.Audience[0] != "cloud-portal" {
		t.Errorf("Audience = %v", d.Audience)
	}
	// The whole point of the field: distinguishes a refresh race from an
	// abandoned session.
	if d.ExpiredBy != 90*time.Second {
		t.Errorf("ExpiredBy = %v, want 90s", d.ExpiredBy)
	}
}

func TestInspectUnexpiredJWTReportsNoExpiry(t *testing.T) {
	now := time.Date(2026, 8, 24, 19, 11, 0, 0, time.UTC)
	withFrozenClock(t, now)

	d := Inspect(signedToken(t, jwt.MapClaims{
		"sub": "abc",
		"exp": now.Add(10 * time.Minute).Unix(),
	}))

	if d.ExpiredBy != 0 {
		t.Errorf("ExpiredBy = %v, want 0 for a live token", d.ExpiredBy)
	}
}

func TestInspectOpaqueToken(t *testing.T) {
	d := Inspect("not-a-jwt-at-all")

	if d.Format != "opaque" {
		t.Errorf("Format = %q, want %q", d.Format, "opaque")
	}
	if d.Fingerprint == "" {
		t.Error("Fingerprint empty; an undecodable token is exactly the case we must still identify")
	}
	if d.Subject != "" || !d.ExpiresAt.IsZero() {
		t.Errorf("expected no JWT fields on an opaque token, got %+v", d)
	}
}

func TestInspectEmptyTokenDoesNotPanic(t *testing.T) {
	d := Inspect("")

	if d == nil {
		t.Fatal("Inspect returned nil; it must never return nil")
	}
	if d.Fingerprint != "" {
		t.Errorf("Fingerprint = %q, want empty for an empty token", d.Fingerprint)
	}
}

// The credential must never reach a log. This is the property that makes
// logging rejected tokens acceptable at all, so it is asserted directly.
func TestLogValuesNeverContainsTheToken(t *testing.T) {
	tok := signedToken(t, jwt.MapClaims{"sub": "abc", "exp": time.Now().Add(time.Hour).Unix()})

	for _, v := range Inspect(tok).LogValues() {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if strings.Contains(tok, s) && len(s) > 12 {
			t.Fatalf("log value %q is a substring of the token", s)
		}
	}
}

// A claim outside the allowlist must not surface, so that a new Zitadel claim
// cannot start leaking into logs without a deliberate code change here.
func TestLogValuesOmitsUnknownClaims(t *testing.T) {
	tok := signedToken(t, jwt.MapClaims{
		"sub":                 "abc",
		"urn:zitadel:iam:org": "super-secret-org-metadata",
	})

	for _, v := range Inspect(tok).LogValues() {
		if s, ok := v.(string); ok && strings.Contains(s, "super-secret-org-metadata") {
			t.Fatal("unallowlisted claim leaked into log values")
		}
	}
}

func TestFingerprintIsStableAndShort(t *testing.T) {
	a, b := fingerprint("some-token"), fingerprint("some-token")

	if a != b {
		t.Errorf("fingerprint not stable: %q vs %q", a, b)
	}
	if len(a) != 12 {
		t.Errorf("fingerprint length = %d, want 12", len(a))
	}
	if a == fingerprint("other-token") {
		t.Error("distinct tokens produced the same fingerprint")
	}
}
