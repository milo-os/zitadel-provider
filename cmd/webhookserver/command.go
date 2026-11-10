package webhookserver

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8sconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	"go.miloapis.com/auth-provider-zitadel/internal/config"
	webhook "go.miloapis.com/auth-provider-zitadel/internal/webhook"
	token "go.miloapis.com/auth-provider-zitadel/pkg/token"
)

// NewAuthenticationWebhookServerCommand returns a cobra command that starts the UserDeactivation
// TokenReview webhook server.
func NewAuthenticationWebhookServerCommand(globalConfig *config.GlobalConfig) *cobra.Command {
	cfg := config.NewWebhookServerConfig()

	cmd := &cobra.Command{
		Use:   "authn-webhook",
		Short: "Runs the User Authentication TokenReview webhook server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWebhookServer(cmd, cfg)
		},
	}

	// Network & Kubernetes flags.
	cmd.Flags().IntVar(&cfg.WebhookPort, "webhook-port", 9443, "Port for the webhook server")
	cmd.Flags().StringVar(&cfg.CertDir, "cert-dir", "/etc/certs", "Directory that contains the TLS certs to use for serving the webhook")
	cmd.Flags().StringVar(&cfg.CertFile, "cert-file", "", "Filename in the directory that contains the TLS cert")
	cmd.Flags().StringVar(&cfg.KeyFile, "key-file", "", "Filename in the directory that contains the TLS private key")

	// Zitadel credential flags: two different keys, not interchangeable.
	cmd.Flags().StringVar(&cfg.ZitadelPrivateKey, "zitadel-private-key", "private-key.json",
		"path to the Zitadel APPLICATION key JSON used for token introspection "+
			"(carries clientId/appId; NOT the service account key)")
	cmd.Flags().StringVar(&cfg.ZitadelServiceAccountKey, "zitadel-service-account-key", "",
		"path to the Zitadel SERVICE ACCOUNT (service user) key JSON used to call the Zitadel API "+
			"(carries userId; required by --account-recovery-template, which mints a passkey "+
			"registration code). This is NOT --zitadel-private-key: an application key cannot mint "+
			"a service-user JWT. Empty disables account recovery rather than failing startup")
	cmd.Flags().StringVar(&cfg.ZitadelDomain, "zitadel-domain", "https://your_domain", "base URL of the Auth Provider instance (e.g., https://auth.example.com)")
	cmd.Flags().DurationVar(&cfg.JwtExpiration, "jwt-expiration", time.Hour, "JWT token expiration duration (e.g., 1h, 30m, 2h30m)")
	cmd.Flags().DurationVar(&cfg.JwtRefreshBefore, "jwt-refresh-before", 5*time.Minute, "Leeway before JWT expiry to consider cache invalid and force refresh (e.g., 5m)")

	// Metrics and probe flags.
	cmd.Flags().StringVar(&cfg.MetricsBindAddress, "metrics-bind-address", ":8080", "address the metrics endpoint binds to")
	cmd.Flags().StringVar(&cfg.HealthProbeBindAddress, "health-probe-bind-address", ":8081",
		"address the probe endpoint binds to; /readyz answers once the webhook server serves, /healthz while the process runs")

	// Email verification flags.
	cmd.Flags().StringVar(&cfg.EmailVerificationTemplate, "email-verification-template", cfg.EmailVerificationTemplate,
		"EmailTemplate resource for signup verification mail; empty disables the endpoint")
	cmd.Flags().StringVar(&cfg.NotificationNamespace, "notification-namespace", cfg.NotificationNamespace,
		"Namespace in which Email resources are created")
	cmd.Flags().StringSliceVar(&cfg.EmailVerificationAllowedOrigins, "email-verification-allowed-origins", nil,
		"Allowlisted origins for returnTo, e.g. https://auth.example.net,http://localhost:3000")
	cmd.Flags().IntVar(&cfg.EmailVerificationExpiryMinutes, "email-verification-expiry-minutes", cfg.EmailVerificationExpiryMinutes,
		"Code lifetime shown to users; must match Zitadel's configured lifetime")
	cmd.Flags().IntVar(&cfg.EmailVerificationUserLookupAttempts, "email-verification-user-lookup-attempts", cfg.EmailVerificationUserLookupAttempts,
		"Retry count when the verification request arrives before create-user-account has provisioned the Milo User")
	cmd.Flags().DurationVar(&cfg.EmailVerificationUserLookupBaseWait, "email-verification-user-lookup-base-wait", cfg.EmailVerificationUserLookupBaseWait,
		"Initial backoff between email-verification user lookup retries")
	// Account recovery flags. The user-lookup retry and the notification namespace are
	// shared with verification: both endpoints race the same provisioning path and
	// create Emails in the same place.
	cmd.Flags().StringVar(&cfg.AccountRecoveryTemplate, "account-recovery-template", cfg.AccountRecoveryTemplate,
		"EmailTemplate resource for self-serve account recovery mail; empty disables the endpoint")
	cmd.Flags().StringSliceVar(&cfg.AccountRecoveryAllowedOrigins, "account-recovery-allowed-origins", nil,
		"Allowlisted origins for returnTo, e.g. https://auth.example.net,http://localhost:3000")
	cmd.Flags().IntVar(&cfg.AccountRecoveryExpiryMinutes, "account-recovery-expiry-minutes", cfg.AccountRecoveryExpiryMinutes,
		"Recovery code lifetime shown to users; must match Zitadel's PasswordlessInitCode lifetime")
	cmd.Flags().DurationVar(&cfg.AccountRecoveryCooldown, "account-recovery-cooldown", cfg.AccountRecoveryCooldown,
		"Minimum gap between recovery mails for one user; 0 disables the cooldown")
	cmd.Flags().IntVar(&cfg.AccountRecoveryMaxPerHour, "account-recovery-max-per-hour", cfg.AccountRecoveryMaxPerHour,
		"Maximum recovery mails per user per hour; 0 disables the cap")

	cmd.Flags().StringSliceVar(&cfg.MailWebhookAllowedClientNames, "mail-webhook-allowed-client-names", nil,
		"Client certificate CNs and/or URI SANs allowed to reach the mail endpoints, e.g. auth-ui; "+
			"empty accepts any client the CA signed")

	cmd.Flags().StringVar(&cfg.ClientCAFile, "client-ca-file", cfg.ClientCAFile,
		"Filename in the directory that contains the CA bundle used to verify client certificates (mTLS)")

	return cmd
}

// validateWebhookConfig rejects a configuration that would expose a mail endpoint.
// Kept out of runWebhookServer so a test can reach it without a cluster.
func validateWebhookConfig(cfg *config.WebhookServerConfig) error {
	// controller-runtime sets RequireAndVerifyClientCert only when ClientCAName is
	// non-empty, so an empty --client-ca-file silently serves these endpoints with no
	// client auth at all. Refuse to start rather than expose them: anyone able to reach
	// the Service could otherwise have us mail a code of their choosing.
	if cfg.EmailVerificationTemplate != "" && cfg.ClientCAFile == "" {
		return fmt.Errorf("--client-ca-file is required when --email-verification-template is set: " +
			"without it the verification endpoint accepts unauthenticated callers")
	}
	if cfg.AccountRecoveryTemplate != "" && cfg.ClientCAFile == "" {
		return fmt.Errorf("--client-ca-file is required when --account-recovery-template is set: " +
			"without it the recovery endpoint accepts unauthenticated callers")
	}
	return nil
}

// unpinnedCallerWarning names the configuration that leaves the mail endpoints open
// to every workload the client CA signed. It is a warning rather than a boot failure
// because the endpoints were shipped that way and a cluster with a single-purpose CA
// is a legitimate deployment; the runbook makes the allowlist a production
// requirement. Kept out of runWebhookServer so a test can reach it without a cluster.
func unpinnedCallerWarning(cfg *config.WebhookServerConfig) string {
	if cfg.EmailVerificationTemplate == "" && cfg.AccountRecoveryTemplate == "" {
		return ""
	}
	if len(webhook.NormalizeClientNames(cfg.MailWebhookAllowedClientNames)) > 0 {
		return ""
	}
	return "mail endpoints accept any client signed by the CA; " +
		"set --mail-webhook-allowed-client-names to pin the caller"
}

func runWebhookServer(cmd *cobra.Command, cfg *config.WebhookServerConfig) error {
	if err := validateWebhookConfig(cfg); err != nil {
		return err
	}

	logf.SetLogger(zap.New(zap.JSONEncoder()))
	log := logf.Log.WithName("authentication-webhook")

	if warning := unpinnedCallerWarning(cfg); warning != "" {
		log.Info("WARNING: " + warning)
	}
	allowedClients := webhook.NormalizeClientNames(cfg.MailWebhookAllowedClientNames)

	log.Info("Starting authentication webhook server",
		"cert_dir", cfg.CertDir,
		"cert_file", cfg.CertFile,
		"key_file", cfg.KeyFile,
		"webhook_port", cfg.WebhookPort,
	)

	log.Info("Creating auth provider introspector",
		"zitadel-private-key", cfg.ZitadelPrivateKey,
		"zitadel-domain", cfg.ZitadelDomain,
		"jwt-expiration", cfg.JwtExpiration,
		"jwt-cache-leeway", cfg.JwtRefreshBefore,
	)

	log.Info("Metrics bind address",
		"metrics-bind-address", cfg.MetricsBindAddress,
	)

	introspector, err := token.NewIntrospector(cfg.ZitadelPrivateKey, cfg.ZitadelDomain, cfg.JwtExpiration, cfg.JwtRefreshBefore)
	if err != nil {
		log.Error(err, "Failed to create auth provider introspector")
		return fmt.Errorf("failed to create auth provider introspector: %w", err)
	}
	log.Info("Successfully created token introspector")

	// Setup Kubernetes client config
	restConfig, err := k8sconfig.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get rest config: %w", err)
	}

	runtimeScheme, err := newScheme()
	if err != nil {
		return err
	}

	log.Info("Creating manager")
	mgr, err := newManager(restConfig, cfg, runtimeScheme)
	if err != nil {
		return err
	}

	// Uncached client, shared by both mail endpoints: each reads a single User per
	// request. The manager's cached client would start an informer over every User
	// for no benefit. Built only when at least one endpoint is configured.
	var directClient client.Client
	if cfg.EmailVerificationTemplate != "" || cfg.AccountRecoveryTemplate != "" {
		directClient, err = client.New(restConfig, client.Options{Scheme: runtimeScheme})
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}
	}

	log.Info("Setting up webhook server")
	hookServer := mgr.GetWebhookServer()

	registerEndpoints(cmd.Context(), hookServer, log, cfg, webhookDeps{
		introspector:   introspector,
		directClient:   directClient,
		allowedClients: allowedClients,
		newMinter:      newRecoveryMinter,
	})

	log.Info("Starting manager")
	return mgr.Start(cmd.Context())
}

// newScheme returns the scheme of the types the webhook reads and writes.
func newScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()
	if err := authenticationv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add authenticationv1 scheme: %w", err)
	}
	if err := iamv1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add iam scheme: %w", err)
	}
	if err := notificationv1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add notification scheme: %w", err)
	}
	return scheme, nil
}

// newManager returns the manager, whose /readyz answers only once the webhook
// server accepts TLS and whose /healthz answers while the process runs.
func newManager(restConfig *rest.Config, cfg *config.WebhookServerConfig, scheme *runtime.Scheme) (manager.Manager, error) {
	mgr, err := manager.New(restConfig, managerOptions(cfg, scheme))
	if err != nil {
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}
	if err := addProbes(mgr, mgr.GetWebhookServer()); err != nil {
		return nil, err
	}
	return mgr, nil
}

// managerOptions returns the manager's options: the scheme, the metrics and
// probe endpoints, and the TLS webhook server.
func managerOptions(cfg *config.WebhookServerConfig, scheme *runtime.Scheme) manager.Options {
	return manager.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: cfg.MetricsBindAddress,
		},
		HealthProbeBindAddress: cfg.HealthProbeBindAddress,
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			CertDir:      cfg.CertDir,
			CertName:     cfg.CertFile,
			KeyName:      cfg.KeyFile,
			ClientCAName: cfg.ClientCAFile,
			Port:         cfg.WebhookPort,
		}),
	}
}

// probeAdder is the part of the manager addProbes needs.
type probeAdder interface {
	AddReadyzCheck(name string, check healthz.Checker) error
	AddHealthzCheck(name string, check healthz.Checker) error
}

// addProbes makes /readyz answer only once the webhook server accepts TLS, and
// /healthz answer while the process serves HTTP. Milo's API server sends every
// token check to this Service, so a pod that is ready before it listens fails
// those checks during a rollout. Liveness checks no dependency: a Zitadel or
// API server outage must not restart every replica.
func addProbes(mgr probeAdder, hookServer ctrlwebhook.Server) error {
	if err := mgr.AddReadyzCheck("webhook", hookServer.StartedChecker()); err != nil {
		return fmt.Errorf("failed to add the webhook server's readiness check: %w", err)
	}
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("failed to add the liveness check: %w", err)
	}
	return nil
}
