package httpactionsserver

import (
	"encoding/base64"
	"sync"
	"testing"
	"time"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

func TestExtractEmailFromIDPUserData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		raw   string
		email string
	}{
		{
			name:  "google nested email",
			raw:   `{"User":{"email":"Ada@Example.com","picture":"https://example.com/a.png"}}`,
			email: "ada@example.com",
		},
		{
			name:  "github top-level email",
			raw:   `{"email":"dev@users.noreply.github.com","avatar_url":"https://avatars.githubusercontent.com/u/1"}`,
			email: "dev@users.noreply.github.com",
		},
		{
			name:  "missing email",
			raw:   `{"User":{"picture":"https://example.com/a.png"}}`,
			email: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := extractEmailFromIDPUserData([]byte(tt.raw)); got != tt.email {
				t.Fatalf("email = %q, want %q", got, tt.email)
			}
		})
	}
}

func TestDecodeIDPUserPayload(t *testing.T) {
	t.Parallel()

	rawJSON := `{"User":{"email":"ada@example.com","picture":"https://example.com/a.png"}}`
	encoded := base64.StdEncoding.EncodeToString([]byte(rawJSON))

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "base64 wrapped", input: encoded, want: rawJSON},
		{name: "raw json", input: rawJSON, want: rawJSON},
		{name: "invalid", input: "not-json", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := decodeIDPUserPayload(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeIDPUserPayload() error = %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestPendingAvatarCache(t *testing.T) {
	t.Parallel()

	pendingAvatars = sync.Map{}

	storePendingAvatar("user@example.com", "https://example.com/a.png", iammiloapiscomv1alpha1.AuthProviderGoogle)
	pending, ok := consumePendingAvatar("user@example.com")
	if !ok {
		t.Fatal("expected pending avatar")
	}
	if pending.avatarURL != "https://example.com/a.png" {
		t.Fatalf("avatarURL = %q", pending.avatarURL)
	}
	if pending.provider != iammiloapiscomv1alpha1.AuthProviderGoogle {
		t.Fatalf("provider = %q", pending.provider)
	}
	if _, ok := consumePendingAvatar("user@example.com"); ok {
		t.Fatal("expected pending avatar to be consumed")
	}

	pendingAvatars.Store("expired@example.com", pendingAvatar{
		avatarURL: "https://example.com/expired.png",
		provider:  iammiloapiscomv1alpha1.AuthProviderGitHub,
		expiresAt: time.Now().Add(-time.Minute),
	})
	if _, ok := consumePendingAvatar("expired@example.com"); ok {
		t.Fatal("expected expired pending avatar to be ignored")
	}
}
