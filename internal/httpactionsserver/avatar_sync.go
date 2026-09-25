package httpactionsserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

const pendingAvatarTTL = 15 * time.Minute

type pendingAvatar struct {
	avatarURL string
	provider  iammiloapiscomv1alpha1.AuthProvider
	expiresAt time.Time
}

var pendingAvatars sync.Map

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func decodeIDPUserPayload(encoded string) ([]byte, error) {
	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" {
		return nil, errors.New("empty idpUser")
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		if json.Valid([]byte(trimmed)) {
			return []byte(trimmed), nil
		}
	}
	if raw, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		if json.Valid(raw) {
			return raw, nil
		}
	}
	return nil, errors.New("idpUser is neither valid JSON nor base64-encoded JSON")
}

func storePendingAvatar(email, avatarURL string, provider iammiloapiscomv1alpha1.AuthProvider) {
	email = normalizeEmail(email)
	if email == "" || avatarURL == "" {
		return
	}
	pendingAvatars.Store(email, pendingAvatar{
		avatarURL: avatarURL,
		provider:  provider,
		expiresAt: time.Now().Add(pendingAvatarTTL),
	})
}

func consumePendingAvatar(email string) (pendingAvatar, bool) {
	email = normalizeEmail(email)
	if email == "" {
		return pendingAvatar{}, false
	}
	value, ok := pendingAvatars.LoadAndDelete(email)
	if !ok {
		return pendingAvatar{}, false
	}
	pending, ok := value.(pendingAvatar)
	if !ok || time.Now().After(pending.expiresAt) {
		return pendingAvatar{}, false
	}
	return pending, true
}

func extractEmailFromIDPUserData(raw []byte) string {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	if user, ok := m["User"].(map[string]any); ok {
		if email, ok := user["email"].(string); ok {
			return normalizeEmail(email)
		}
	}
	if email, ok := m["email"].(string); ok {
		return normalizeEmail(email)
	}
	return ""
}

func (s *Server) patchUserAvatar(
	ctx context.Context,
	log logr.Logger,
	userID string,
	avatarURL string,
	provider iammiloapiscomv1alpha1.AuthProvider,
	fieldManager string,
) error {
	current := &iammiloapiscomv1alpha1.User{}
	if err := s.k8sClient.Get(ctx, client.ObjectKey{Name: userID}, current); err != nil {
		return err
	}
	original := current.DeepCopy()
	current.Status.AvatarURL = avatarURL
	current.Status.LastLoginProvider = provider
	if err := s.k8sClient.Status().Patch(ctx, current, client.MergeFrom(original), client.FieldOwner(fieldManager)); err != nil {
		return err
	}
	log.Info("Patched user avatar", "userId", userID, "avatarURL", avatarURL, "idpProvider", provider)
	return nil
}

func (s *Server) applyPendingAvatarByEmail(
	ctx context.Context,
	log logr.Logger,
	userID, email, fieldManager string,
) bool {
	pending, ok := consumePendingAvatar(email)
	if !ok {
		return false
	}
	if err := s.patchUserAvatar(ctx, log, userID, pending.avatarURL, pending.provider, fieldManager); err != nil {
		log.Error(err, "Failed to apply pending avatar", "userId", userID, "email", email)
		storePendingAvatar(email, pending.avatarURL, pending.provider)
		return false
	}
	return true
}
