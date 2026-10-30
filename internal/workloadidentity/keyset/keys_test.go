package keyset

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Public example keys from RFC 8037 (Ed25519) and RFC 7517 (P-256).
const (
	edX = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	ecX = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"
	ecY = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
)

func rsaModulus(bytesLong int) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xc5}, bytesLong))
}

func TestUsableKeys(t *testing.T) {
	ed := func(kid, extra string) string {
		return fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":%q,"x":%q%s}`, kid, edX, extra)
	}
	// The private members below are placeholders, not key material.
	cases := []struct {
		name    string
		key     string
		usable  bool
		because string
	}{
		{"an Ed25519 key", ed("k1", ""), true, ""},
		{"a P-256 key with a matching alg", fmt.Sprintf(`{"kty":"EC","crv":"P-256","kid":"k1","alg":"ES256","x":%q,"y":%q}`, ecX, ecY), true, ""},
		{"a 2048-bit RSA key", fmt.Sprintf(`{"kty":"RSA","kid":"k1","use":"sig","n":%q,"e":"AQAB"}`, rsaModulus(256)), true, ""},
		{"a 1024-bit RSA key", fmt.Sprintf(`{"kty":"RSA","kid":"k1","n":%q,"e":"AQAB"}`, rsaModulus(128)), false, "at least 2048 bits"},
		{"an RSA key with no exponent", fmt.Sprintf(`{"kty":"RSA","kid":"k1","n":%q}`, rsaModulus(256)), false, "exponent"},
		{"an encryption key", ed("k1", `,"use":"enc"`), false, `"use" is not "sig"`},
		{"an alg that does not match the key", ed("k1", `,"alg":"RS256"`), false, "does not match"},
		{"the fully specified Ed25519 alg name", ed("k1", `,"alg":"Ed25519"`), false, "does not match"},
		{"a key with no kid", fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, edX), false, "no kid"},
		{"a P-384 key", fmt.Sprintf(`{"kty":"EC","crv":"P-384","kid":"k1","x":%q,"y":%q}`, ecX, ecY), false, "only Ed25519, P-256 and RSA"},
		{"a short Ed25519 key", `{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"AAAA"}`, false, "32 bytes"},
		{"a padded base64url member", `{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"` + edX + `="}`, false, "32 bytes"},
		{"a key with members a verifier does not read", ed("k1", `,"x5t":"abc"`), true, ""},
		{"an empty alg", ed("k1", `,"alg":""`), false, "does not match"},
		{"an empty use", ed("k1", `,"use":""`), false, `"use" is not "sig"`},
		{"a null alg is absent", ed("k1", `,"alg":null`), true, ""},
		{"a base64url member with a line break", `{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"` + edX[:20] + `\n` + edX[20:] + `"}`, false, "32 bytes"},
		{"a key with a private member", ed("k1", `,"d":"AA"`), false, `private key member "d"`},
		{"a private member under an escaped name", ed("k1", `,"\u0064":"AA"`), false, `private key member "d"`},
		{"an RSA key with other primes", fmt.Sprintf(`{"kty":"RSA","kid":"k1","n":%q,"e":"AQAB","oth":[]}`, rsaModulus(256)), false, `private key member "oth"`},
		{"a member that appears twice", ed("k1", `,"x":"AA"`), false, `member "x" appears twice`},
	}
	// A usable key is published unchanged, except for these, which lose members a verifier does not read.
	published := map[string]string{
		"a key with members a verifier does not read": ed("k1", ""),
		"a null alg is absent":                        ed("k1", ""),
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, dropped, err := UsableKeys(`{"keys":[` + tc.key + `]}`)
			if err != nil {
				t.Fatalf("UsableKeys: %v", err)
			}
			var got struct{ Keys []json.RawMessage }
			if err := json.Unmarshal([]byte(set), &got); err != nil {
				t.Fatalf("the published set is not JSON: %v", err)
			}
			if tc.usable {
				if len(got.Keys) != 1 || len(dropped) != 0 {
					t.Fatalf("kept %d, dropped %v; want the key kept", len(got.Keys), dropped)
				}
				want, ok := published[tc.name]
				if !ok {
					want = tc.key
				}
				var compact bytes.Buffer
				_ = json.Compact(&compact, []byte(want))
				if string(got.Keys[0]) != compact.String() {
					t.Fatalf("published %s; want %s", got.Keys[0], compact.String())
				}
				return
			}
			if len(got.Keys) != 0 || len(dropped) != 1 || !strings.Contains(dropped[0], tc.because) {
				t.Fatalf("kept %d, dropped %v; want the key dropped because %q", len(got.Keys), dropped, tc.because)
			}
			if strings.Contains(dropped[0], `"AA"`) {
				t.Fatalf("the reason %q repeats a member's value", dropped[0])
			}
		})
	}
}

func TestUsableKeysKeepsOrderAndDropsRepeatedKids(t *testing.T) {
	ec := fmt.Sprintf(`{"kty":"EC","crv":"P-256","kid":"k2","x":%q,"y":%q}`, ecX, ecY)
	ed := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":"k1","x":%q}`, edX)
	repeat := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":"k2","x":%q}`, edX)
	set, dropped, err := UsableKeys(`{"keys":[` + ec + `,` + ed + `,` + repeat + `]}`)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"keys":[` + ec + `,` + ed + `]}`; set != want {
		t.Fatalf("published %s; want %s", set, want)
	}
	if len(dropped) != 1 || !strings.Contains(dropped[0], "kid is not unique") {
		t.Fatalf("dropped %v; want the repeated kid dropped", dropped)
	}
}

func TestUsableKeysRefusesADocumentThatIsNotAKeySet(t *testing.T) {
	if _, _, err := UsableKeys("not json"); err == nil {
		t.Fatal("accepted a document that is not JSON")
	}
	set, dropped, err := UsableKeys(`{"keys":[]}`)
	if err != nil || set != `{"keys":[]}` || len(dropped) != 0 {
		t.Fatalf("an empty set gave %q, %v, %v", set, dropped, err)
	}
}
