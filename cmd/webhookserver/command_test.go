package webhookserver

import (
	"strings"
	"testing"

	"go.miloapis.com/auth-provider-zitadel/internal/config"
)

func TestValidateWebhookConfig(t *testing.T) {
	for name, tc := range map[string]struct {
		template string
		clientCA string
		wantErr  bool
	}{
		// The endpoint is registered but nothing authenticates the caller.
		"endpoint on, no client CA": {template: "verify-tpl", clientCA: "", wantErr: true},
		"endpoint on, client CA":    {template: "verify-tpl", clientCA: "ca.crt", wantErr: false},
		// No template means no route, so there is nothing to protect and the absent
		// CA must not block the TokenReview webhook from starting.
		"endpoint off, no client CA": {template: "", clientCA: "", wantErr: false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.NewWebhookServerConfig()
			cfg.EmailVerificationTemplate = tc.template
			cfg.ClientCAFile = tc.clientCA

			err := validateWebhookConfig(cfg)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected startup to fail: the endpoint would serve unauthenticated callers")
				}
				if !strings.Contains(err.Error(), "--client-ca-file is required") {
					t.Fatalf("error should name the missing flag, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

// The recovery endpoint mails a live registration code, so it carries the same mTLS
// requirement as verification: an unauthenticated caller could otherwise have us mail
// a working code of their choosing.
func TestValidateWebhookConfig_RecoveryTemplateRequiresClientCA(t *testing.T) {
	for name, tc := range map[string]struct {
		recoveryTemplate string
		clientCA         string
		wantErr          bool
	}{
		"recovery on, no client CA":  {recoveryTemplate: "recovery-tpl", clientCA: "", wantErr: true},
		"recovery on, client CA":     {recoveryTemplate: "recovery-tpl", clientCA: "ca.crt", wantErr: false},
		"recovery off, no client CA": {recoveryTemplate: "", clientCA: "", wantErr: false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.NewWebhookServerConfig()
			// Verification stays off, so only the recovery template can trip the rule.
			cfg.EmailVerificationTemplate = ""
			cfg.AccountRecoveryTemplate = tc.recoveryTemplate
			cfg.ClientCAFile = tc.clientCA

			err := validateWebhookConfig(cfg)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected startup to fail: the recovery endpoint would serve unauthenticated callers")
				}
				if !strings.Contains(err.Error(), "--client-ca-file is required") {
					t.Fatalf("error should name the missing flag, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

// S1. An empty allowlist is a supported configuration — mTLS still proves the caller
// was signed by the configured CA — but it means every workload holding a cert from
// that CA can reach the mail endpoints. That has to be loud at startup rather than
// discovered later, so the warning is a function a test can reach without a cluster,
// the same way validateWebhookConfig is.
func TestUnpinnedCallerWarning(t *testing.T) {
	tests := map[string]struct {
		cfg  config.WebhookServerConfig
		warn bool
	}{
		"no mail endpoint, nothing to warn about": {
			config.WebhookServerConfig{}, false,
		},
		"recovery on, no allowlist": {
			config.WebhookServerConfig{AccountRecoveryTemplate: "tpl", ClientCAFile: "ca.crt"}, true,
		},
		"verification on, no allowlist": {
			config.WebhookServerConfig{EmailVerificationTemplate: "tpl", ClientCAFile: "ca.crt"}, true,
		},
		"an empty flag value is not an allowlist": {
			config.WebhookServerConfig{
				AccountRecoveryTemplate:       "tpl",
				ClientCAFile:                  "ca.crt",
				MailWebhookAllowedClientNames: []string{""},
			}, true,
		},
		"allowlist set, nothing to warn about": {
			config.WebhookServerConfig{
				AccountRecoveryTemplate:       "tpl",
				ClientCAFile:                  "ca.crt",
				MailWebhookAllowedClientNames: []string{"auth-ui"},
			}, false,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := unpinnedCallerWarning(&tt.cfg)

			if tt.warn && got == "" {
				t.Fatal("expected a warning")
			}
			if !tt.warn && got != "" {
				t.Fatalf("expected no warning, got %q", got)
			}
		})
	}
}
