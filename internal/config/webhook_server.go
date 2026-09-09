package config

import "time"

// WebhookServerConfig holds the configuration for the webhook server.
type WebhookServerConfig struct {
	CertDir            string
	CertFile           string
	KeyFile            string
	WebhookPort        int
	ZitadelPrivateKey  string
	ZitadelDomain      string
	JwtExpiration      time.Duration
	JwtRefreshBefore   time.Duration
	MetricsBindAddress string

	// EmailVerificationTemplate is the EmailTemplate resource used for signup
	// verification mail. Empty disables the endpoint entirely — the route is not
	// registered, so an unconfigured deployment cannot send.
	EmailVerificationTemplate string
	// NotificationNamespace is where Email resources are created.
	NotificationNamespace string
	// EmailVerificationAllowedOrigins is the returnTo allowlist. Empty rejects every
	// request: a missing value must never read as "allow any host".
	EmailVerificationAllowedOrigins []string
	// EmailVerificationExpiryMinutes mirrors Zitadel's configured code lifetime. It is
	// a COPY of state we do not own; if the lifetime changes in Zitadel this number
	// silently starts lying to users.
	EmailVerificationExpiryMinutes int
	// EmailVerificationUserLookupAttempts is how many times to retry fetching the
	// Milo User when the verification request arrives before create-user-account
	// has provisioned it.
	EmailVerificationUserLookupAttempts int
	// EmailVerificationUserLookupBaseWait is the initial backoff between those
	// retries.
	EmailVerificationUserLookupBaseWait time.Duration
	// AccountRecoveryTemplate is the EmailTemplate resource used for self-serve
	// account-recovery mail. Empty disables the endpoint entirely — the route is not
	// registered, so an unconfigured deployment cannot send.
	AccountRecoveryTemplate string
	// AccountRecoverySupportTemplate is the template whose copy says Datum Support
	// sent the link. The request selects between the two names; it can never supply
	// one, so a compromised caller cannot pick an arbitrary template.
	AccountRecoverySupportTemplate string
	// AccountRecoveryAllowedOrigins is the returnTo allowlist for recovery links.
	// Empty rejects every request: a missing value must never read as "allow any host".
	AccountRecoveryAllowedOrigins []string
	// AccountRecoveryExpiryMinutes mirrors Zitadel's configured PasswordlessInitCode
	// lifetime. It is a COPY of state we do not own; if the lifetime changes in
	// Zitadel this number silently starts lying to users.
	AccountRecoveryExpiryMinutes int

	// ClientCAFile enables mTLS. Without it the endpoint would accept any caller that
	// can reach the Service, so runWebhookServer refuses to start when either mail
	// template is set and this is not.
	//
	// It is a FILENAME inside CertDir, not a path: controller-runtime joins the two.
	ClientCAFile string
}

// NewWebhookServerConfig creates a new WebhookServerConfig with default values.
func NewWebhookServerConfig() *WebhookServerConfig {
	return &WebhookServerConfig{
		CertDir:     "/etc/certs",
		CertFile:    "server.crt",
		KeyFile:     "server.key",
		WebhookPort: 9443,

		NotificationNamespace:               "milo-system",
		EmailVerificationExpiryMinutes:      60,
		AccountRecoveryExpiryMinutes:        60,
		EmailVerificationUserLookupAttempts: 5,
		EmailVerificationUserLookupBaseWait: 200 * time.Millisecond,
	}
}
