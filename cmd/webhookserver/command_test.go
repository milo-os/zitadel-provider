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
