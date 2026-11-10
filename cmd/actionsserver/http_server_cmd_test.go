package actionsserver

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"go.miloapis.com/auth-provider-zitadel/internal/config"
)

func TestCreateZitadelClient_Validation(t *testing.T) {
	// Clean up environment variables to ensure test isolation
	originalKeyPath := os.Getenv("ZITADEL_KEY_PATH")
	originalMachineKeyPath := os.Getenv("ZITADEL_MACHINE_ACCOUNT_KEY_PATH")
	originalAPI := os.Getenv("ZITADEL_API")
	originalIssuer := os.Getenv("ZITADEL_ISSUER")

	defer func() {
		_ = os.Setenv("ZITADEL_KEY_PATH", originalKeyPath)
		_ = os.Setenv("ZITADEL_MACHINE_ACCOUNT_KEY_PATH", originalMachineKeyPath)
		_ = os.Setenv("ZITADEL_API", originalAPI)
		_ = os.Setenv("ZITADEL_ISSUER", originalIssuer)
	}()

	_ = os.Setenv("ZITADEL_KEY_PATH", "")
	_ = os.Setenv("ZITADEL_MACHINE_ACCOUNT_KEY_PATH", "")
	_ = os.Setenv("ZITADEL_API", "env-api.zitadel.cloud")
	_ = os.Setenv("ZITADEL_ISSUER", "https://env-api.zitadel.cloud")

	ctx := context.Background()

	t.Run("returns nil, nil if issuer is empty", func(t *testing.T) {
		client, err := createZitadelClient(ctx, "", "domain.com", "key.json", 1*time.Hour)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if client != nil {
			t.Error("expected client to be nil")
		}
	})

	t.Run("returns nil, nil if domain is empty", func(t *testing.T) {
		client, err := createZitadelClient(ctx, "https://issuer.com", "", "key.json", 1*time.Hour)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if client != nil {
			t.Error("expected client to be nil")
		}
	})

	t.Run("returns nil, nil if key path is empty (both flag and env)", func(t *testing.T) {
		_ = os.Setenv("ZITADEL_KEY_PATH", "")
		_ = os.Setenv("ZITADEL_MACHINE_ACCOUNT_KEY_PATH", "")
		client, err := createZitadelClient(ctx, "https://issuer.com", "domain.com", "", 1*time.Hour)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if client != nil {
			t.Error("expected client to be nil")
		}
	})

	t.Run("uses key path from ZITADEL_KEY_PATH env if flag is empty", func(t *testing.T) {
		_ = os.Setenv("ZITADEL_KEY_PATH", "env-key.json")
		_ = os.Setenv("ZITADEL_MACHINE_ACCOUNT_KEY_PATH", "")
		// This should try to instantiate NewSDK and fail with "open env-key.json: no such file or directory"
		_, err := createZitadelClient(ctx, "https://issuer.com", "domain.com", "", 1*time.Hour)
		if err == nil {
			t.Error("expected error due to missing file, got nil")
		} else if !strings.Contains(err.Error(), "env-key.json") && !strings.Contains(err.Error(), "no such file") {
			t.Errorf("expected error about env-key.json, got: %v", err)
		}
	})

	t.Run("uses key path from ZITADEL_MACHINE_ACCOUNT_KEY_PATH env if ZITADEL_KEY_PATH is empty", func(t *testing.T) {
		_ = os.Setenv("ZITADEL_KEY_PATH", "")
		_ = os.Setenv("ZITADEL_MACHINE_ACCOUNT_KEY_PATH", "machine-env-key.json")
		// This should try to instantiate NewSDK and fail with "open machine-env-key.json: no such file or directory"
		_, err := createZitadelClient(ctx, "https://issuer.com", "domain.com", "", 1*time.Hour)
		if err == nil {
			t.Error("expected error due to missing file, got nil")
		} else if !strings.Contains(err.Error(), "machine-env-key.json") && !strings.Contains(err.Error(), "no such file") {
			t.Errorf("expected error about machine-env-key.json, got: %v", err)
		}
	})
}

func TestHealthProbeFlag(t *testing.T) {
	cmd := NewActionsServerCommand(&config.GlobalConfig{})

	flag := cmd.Flags().Lookup("health-probe-bind-address")
	if flag == nil {
		t.Fatal("no --health-probe-bind-address flag: the kubelet cannot reach a liveness endpoint")
	}
	if flag.DefValue != "" {
		t.Errorf("default %q opens a listener nobody asked for; want it off by default", flag.DefValue)
	}
	if err := cmd.Flags().Set("health-probe-bind-address", ":8081"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
}
