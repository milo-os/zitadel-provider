package token

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Diagnostics carries the non-secret parts of a bearer token so a rejected
// authentication can be explained after the fact.
//
// Zitadel cannot tell us why a token was refused. RFC 7662 §2.2 says an
// introspection endpoint returns a bare {"active": false} for any token that is
// expired, revoked, malformed, or issued to another audience, and Zitadel
// follows that to the letter — deliberately, so introspection cannot be used to
// probe token state. The reason therefore has to come from the token we were
// handed, not from the answer we got back.
//
// Every field here is drawn from the JWT payload WITHOUT signature
// verification. That is safe only because this type feeds logs and nothing
// else: an attacker can put anything in an unverified payload, so these values
// describe what the caller *claimed*, never what the caller *is*. Never let an
// authentication or authorization decision read from this struct.
type Diagnostics struct {
	// Format is "jwt" for a decodable JWS payload, "opaque" otherwise. Zitadel
	// issues both, and an opaque token is not a defect.
	Format string

	Subject  string
	Issuer   string
	Audience []string
	ClientID string

	IssuedAt  time.Time
	ExpiresAt time.Time

	// ExpiredBy is how long ago the token expired, zero when it has not.
	// Reported separately because "expired 4 seconds ago" and "expired nine
	// days ago" point at completely different faults — a refresh race versus an
	// abandoned session — and that distinction is invisible in a raw exp.
	ExpiredBy time.Duration

	// Fingerprint is the first 12 hex characters of the token's SHA-256. It
	// correlates repeated rejections of the SAME token across requests, pods,
	// and services without putting the credential in a log. Truncated because
	// only equality matters here.
	Fingerprint string
}

// safeClaims is the allowlist of payload fields we are willing to log. Zitadel
// access tokens can carry org metadata, roles, and custom claims; decoding into
// a fixed struct rather than a map guarantees a new upstream claim can never
// start leaking into logs on its own.
type safeClaims struct {
	// RegisteredClaims supplies sub/iss/aud/iat/exp and, by implementing
	// jwt.Claims, lets this type be a ParseUnverified target directly.
	jwt.RegisteredClaims

	// ClientID is Zitadel's machine-identity claim; it has no registered
	// equivalent, and EffectiveUsername keys service accounts off it.
	ClientID string `json:"client_id,omitempty"`
}

// Inspect extracts loggable diagnostics from a bearer token.
//
// It never returns an error and never returns nil: a token we cannot parse is
// exactly the case we most need described, so an undecodable token yields a
// Diagnostics carrying its format and fingerprint alone.
func Inspect(token string) *Diagnostics {
	d := &Diagnostics{
		Format:      "opaque",
		Fingerprint: fingerprint(token),
	}

	var claims safeClaims
	// ParserOption-free ParseUnverified: we hold no key for the issuer here, and
	// the introspection call above is what actually establishes trust.
	if _, _, err := jwt.NewParser().ParseUnverified(token, &claims); err != nil {
		return d
	}

	d.Format = "jwt"
	d.Subject = claims.Subject
	d.Issuer = claims.Issuer
	d.Audience = claims.Audience
	d.ClientID = claims.ClientID

	if claims.IssuedAt != nil {
		d.IssuedAt = claims.IssuedAt.Time
	}
	if claims.ExpiresAt != nil {
		d.ExpiresAt = claims.ExpiresAt.Time
		if elapsed := nowFunc().Sub(d.ExpiresAt); elapsed > 0 {
			d.ExpiredBy = elapsed.Truncate(time.Second)
		}
	}

	return d
}

// LogValues renders the diagnostics as alternating key/value pairs for
// logr-style structured logging. Zero-valued fields are omitted so an opaque
// token does not emit a row of empty JWT columns.
func (d *Diagnostics) LogValues() []any {
	if d == nil {
		return nil
	}

	kv := []any{"token_format", d.Format, "token_fingerprint", d.Fingerprint}

	if d.Subject != "" {
		kv = append(kv, "token_sub", d.Subject)
	}
	if d.Issuer != "" {
		kv = append(kv, "token_iss", d.Issuer)
	}
	if len(d.Audience) > 0 {
		kv = append(kv, "token_aud", d.Audience)
	}
	if d.ClientID != "" {
		kv = append(kv, "token_client_id", d.ClientID)
	}
	if !d.IssuedAt.IsZero() {
		kv = append(kv, "token_iat", d.IssuedAt.UTC().Format(time.RFC3339))
	}
	if !d.ExpiresAt.IsZero() {
		kv = append(kv, "token_exp", d.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if d.ExpiredBy > 0 {
		kv = append(kv, "token_expired_by", d.ExpiredBy.String())
	}

	return kv
}

func fingerprint(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:12]
}
