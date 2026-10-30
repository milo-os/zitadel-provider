// Package keyset verifies the signing keys of workload identity issuers and publishes the usable ones in
// each issuer's status.
package keyset

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// minRSAModulusBytes is 2048 bits: shorter RSA keys are not usable.
const minRSAModulusBytes = 256

var base64url = base64.RawURLEncoding.Strict()

// publicMembers are the members a published key keeps: what a verifier reads to check a signature.
var publicMembers = map[string]bool{"kty": true, "kid": true, "use": true, "alg": true, "crv": true,
	"x": true, "y": true, "n": true, "e": true}

// privateMembers are the JSON Web Key members that hold private key material (RFC 7518 section 6).
var privateMembers = map[string]bool{"d": true, "p": true, "q": true, "dp": true, "dq": true, "qi": true,
	"oth": true, "k": true}

// jwk holds the members a verifier reads. "alg" and "use" are pointers because an empty string is present,
// not absent: a verifier refuses it.
type jwk struct {
	Kty string  `json:"kty"`
	Kid string  `json:"kid"`
	Alg *string `json:"alg"`
	Crv string  `json:"crv"`
	X   string  `json:"x"`
	Y   string  `json:"y"`
	N   string  `json:"n"`
	E   string  `json:"e"`
	Use *string `json:"use"`
}

// UsableKeys returns the keys of a JSON Web Key Set that a token verifier can use, as a compact key set
// in their original order, and a reason for each key it left out. A key is usable when it is an Ed25519
// key (EdDSA), a P-256 key (ES256) or an RSA key of at least 2048 bits (RS256); its "use" is "sig" or
// absent; its "alg", when present, names that algorithm; and it has a "kid" no other usable key has.
// A key that carries private key material is left out, so it is never published. Each kept key is
// published with its public members only, in their original order. An error means the document is not a
// key set at all.
func UsableKeys(document string) (string, []string, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal([]byte(document), &set); err != nil {
		return "", nil, fmt.Errorf("not a JSON Web Key Set: %w", err)
	}
	kept := []json.RawMessage{}
	seen := map[string]bool{}
	var dropped []string
	for i, raw := range set.Keys {
		var key jwk
		if err := json.Unmarshal(raw, &key); err != nil {
			dropped = append(dropped, fmt.Sprintf("key %d: not a JSON object", i))
			continue
		}
		public, reason := publicPart(raw)
		if reason != "" {
			dropped = append(dropped, fmt.Sprintf("key %d (kid %q): %s", i, key.Kid, reason))
			continue
		}
		if reason := unusable(key); reason != "" {
			dropped = append(dropped, fmt.Sprintf("key %d (kid %q): %s", i, key.Kid, reason))
			continue
		}
		if seen[key.Kid] {
			dropped = append(dropped, fmt.Sprintf("key %d (kid %q): kid is not unique", i, key.Kid))
			continue
		}
		seen[key.Kid] = true
		kept = append(kept, public)
	}
	out, err := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{kept})
	if err != nil {
		return "", nil, err
	}
	return string(out), dropped, nil
}

// publicPart returns a key's public members, compact and in their original order, or a reason to leave the
// key out: it carries private key material, or a member appears twice.
func publicPart(raw json.RawMessage) (json.RawMessage, string) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, "not a JSON object"
	}
	var out bytes.Buffer
	out.WriteByte('{')
	names := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, "not a JSON object"
		}
		name, _ := token.(string)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, "not a JSON object"
		}
		if names[name] {
			return nil, fmt.Sprintf("member %q appears twice", name)
		}
		names[name] = true
		if privateMembers[name] {
			return nil, fmt.Sprintf("it carries the private key member %q, so it is not published; "+
				"remove it from the key set and rotate the key", name)
		}
		if !publicMembers[name] || string(value) == "null" {
			continue
		}
		if out.Len() > 1 {
			out.WriteByte(',')
		}
		quoted, _ := json.Marshal(name)
		out.Write(quoted)
		out.WriteByte(':')
		if err := json.Compact(&out, value); err != nil {
			return nil, "not a JSON object"
		}
	}
	out.WriteByte('}')
	return out.Bytes(), ""
}

// unusable says why a key cannot verify tokens, or returns "" when it can.
func unusable(key jwk) string {
	if key.Use != nil && *key.Use != "sig" {
		return `"use" is not "sig"`
	}
	if key.Kid == "" {
		return "no kid"
	}
	decodedLen := func(value string) int {
		decoded, err := base64url.DecodeString(value)
		if value == "" || err != nil || strings.ContainsAny(value, "\r\n") {
			return -1
		}
		return len(decoded)
	}
	var algorithm string
	switch {
	case key.Kty == "OKP" && key.Crv == "Ed25519":
		if decodedLen(key.X) != 32 {
			return "an Ed25519 key must be 32 bytes"
		}
		algorithm = "EdDSA"
	case key.Kty == "EC" && key.Crv == "P-256":
		if decodedLen(key.X) != 32 || decodedLen(key.Y) != 32 {
			return "a P-256 key's coordinates must be 32 bytes each"
		}
		algorithm = "ES256"
	case key.Kty == "RSA":
		if decodedLen(key.E) < 1 {
			return "an RSA key needs an exponent"
		}
		if decodedLen(key.N) < minRSAModulusBytes {
			return "an RSA key must be at least 2048 bits"
		}
		algorithm = "RS256"
	default:
		return "only Ed25519, P-256 and RSA keys are supported"
	}
	if key.Alg != nil && *key.Alg != algorithm {
		return fmt.Sprintf(`"alg" %q does not match the key, which is %s`, *key.Alg, algorithm)
	}
	return ""
}
