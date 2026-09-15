package actionsserver

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/zitadel/zitadel/pkg/actions"
	"go.miloapis.com/auth-provider-zitadel/internal/config"
	"go.miloapis.com/auth-provider-zitadel/internal/httpactionsserver"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	signature "go.miloapis.com/auth-provider-zitadel/pkg/zitadel-actions/signature"
	iamiamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// NewActionsServerCommand creates the cobra command to start the actions HTTP server.
// This thin wrapper lives under cmd/ and delegates the actual server implementation
// to the internal/httpactionsserver package.
func NewActionsServerCommand(globalConfig *config.GlobalConfig) *cobra.Command {
	log := logf.Log.WithName("actions-server-cmd")
	cfg := httpactionsserver.NewServerConfig()

	var (
		zitadelIssuer               string
		zitadelAPI                  string
		zitadelKeyPath              string
		defaultMachineKeyExpiration time.Duration
	)

	cmd := &cobra.Command{
		Use:   "actions-server",
		Short: "Run the HTTP server that exposes zitadel v2/actions webhook endpoints",
		Long: `Start a lightweight HTTP server that provides the v1/actions/create-user-account endpoint.
If a TLS certificate and key are provided, the server will start in HTTPS mode. Otherwise, it will fall back to HTTP.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Info("Starting actions server",
				"addr", cfg.Addr,
				"tlsEnabled", cfg.CertFile != "" && cfg.KeyFile != "",
				"http2Disabled", cfg.DisableHTTP2,
				"signatureValidation", !cfg.DisableSignatureValidation,
			)

			// Load kubeconfig
			log.Info("Loading kubeconfig", "path", cfg.Kubeconfig)
			k8sConfig, err := clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
			if err != nil {
				log.Error(err, "Failed to load kubeconfig", "path", cfg.Kubeconfig)
				return fmt.Errorf("unable to load kubeconfig from %s: %w", cfg.Kubeconfig, err)
			}
			log.V(1).Info("Successfully loaded kubeconfig")

			// Build a scheme that knows about IAM APIs
			log.Info("Building Kubernetes scheme with IAM APIs")
			scheme := runtime.NewScheme()
			utilruntime.Must(iamiamv1alpha1.AddToScheme(scheme))
			utilruntime.Must(notificationv1alpha1.AddToScheme(scheme))
			log.V(1).Info("Successfully built Kubernetes scheme")

			log.Info("Creating Kubernetes client")
			k8sClient, err := client.New(k8sConfig, client.Options{Scheme: scheme})
			if err != nil {
				log.Error(err, "Failed to create Kubernetes client")
				return err
			}
			log.V(1).Info("Successfully created Kubernetes client")

			// If signature validation is enabled, validate the Zitadel Webhook Payload
			log.Info("Configuring signature validation", "enabled", !cfg.DisableSignatureValidation)
			var validateSignatureFunc httpactionsserver.ValidateSignatureFunc
			if cfg.DisableSignatureValidation {
				log.Info("Signature validation disabled, using noop validator")
				validateSignatureFunc = signature.NoopValidatePayload
			} else {
				if cfg.SigningKey == "" {
					log.Error(nil, "Signing key is required when signature validation is enabled")
					return fmt.Errorf("signing key is required when signature validation is enabled")
				}
				log.Info("Using Zitadel signature validation")
				validateSignatureFunc = actions.ValidatePayload
			}

			// Initialize the Zitadel SDK client. This is intentionally
			// non-fatal: the actions server runs as a sidecar in the Zitadel
			// pod, and blocking startup on reaching Zitadel deadlocks the pod.
			// The zitadel Service only routes to a Ready pod, and the pod is
			// not Ready until this container is up — so if we exit here, the
			// Service never gets an endpoint and this container can never
			// reach Zitadel. Start anyway and retry in the background.
			zitadelSDKClient, err := createZitadelClient(
				cmd.Context(),
				zitadelIssuer,
				zitadelAPI,
				zitadelKeyPath,
				defaultMachineKeyExpiration,
			)
			switch {
			case err != nil:
				log.Error(err, "Failed to initialize Zitadel SDK client; starting without session endpoints and retrying in background")
			case zitadelSDKClient != nil:
				log.V(1).Info("Successfully initialized Zitadel SDK client")
			default:
				log.Info("Zitadel SDK client configuration not provided; session endpoints will be unavailable")
			}

			// Start the server
			log.Info("Starting HTTP actions server")
			svr := httpactionsserver.NewServer(cfg, k8sClient, validateSignatureFunc, zitadelSDKClient)

			// If the SDK was configured but unreachable at startup, keep
			// retrying in the background and install the client once Zitadel
			// becomes available.
			if err != nil {
				go retryZitadelClient(cmd.Context(), log, svr, zitadelIssuer, zitadelAPI, zitadelKeyPath, defaultMachineKeyExpiration)
			}

			return svr.Start()
		},
	}

	// Server flags
	cmd.Flags().StringVar(&cfg.Addr, "addr", cfg.Addr, "The address the HTTP server binds to (e.g. :8080)")
	cmd.Flags().StringVar(&cfg.CertFile, "cert-file", cfg.CertFile, "Path to the TLS certificate file (optional)")
	cmd.Flags().StringVar(&cfg.KeyFile, "key-file", cfg.KeyFile, "Path to the TLS private key file (optional)")
	cmd.Flags().BoolVar(&cfg.DisableHTTP2, "disable-http2", cfg.DisableHTTP2, "Disable HTTP/2 when serving with TLS (forces http/1.1)")
	cmd.Flags().StringVar(&cfg.Kubeconfig, "kubeconfig", "", "Path to the kubeconfig file.")
	cmd.Flags().StringVar(&cfg.SigningKey, "signing-key", "", "Signing key for validating Zitadel webhook signatures. Provided by Zitadel when creating the Webhook Target.")
	cmd.Flags().BoolVar(&cfg.DisableSignatureValidation, "disable-signature-validation", cfg.DisableSignatureValidation, "Disable signature validation of Zitadel webhook payloads")

	// Notification flags
	cmd.Flags().StringVar(&cfg.SuspiciousLoginEmailTemplate, "suspicious-login-email-template", cfg.SuspiciousLoginEmailTemplate, "Name of the EmailTemplate cluster resource used for suspicious login notifications")
	cmd.Flags().StringVar(&cfg.PasskeyAddedEmailTemplate, "passkey-added-email-template", cfg.PasskeyAddedEmailTemplate, "Name of the EmailTemplate cluster resource used for passkey-added notifications")
	cmd.Flags().StringVar(&cfg.PasskeyRemovedEmailTemplate, "passkey-removed-email-template", cfg.PasskeyRemovedEmailTemplate, "Name of the EmailTemplate cluster resource used for passkey-removed notifications")
	cmd.Flags().StringVar(&cfg.NotificationNamespace, "notification-namespace", cfg.NotificationNamespace, "Namespace in which Email resources are created")

	// GraphQL Gateway flags
	cmd.Flags().StringVar(&cfg.GraphQLGatewayURL, "graphql-gateway-url", cfg.GraphQLGatewayURL, "GraphQL gateway endpoint used for IP geolocation (empty disables geolocation)")
	cmd.Flags().StringVar(&cfg.GraphQLGatewayCACertFile, "graphql-gateway-ca-cert", cfg.GraphQLGatewayCACertFile, "Path to PEM CA cert used to verify the gateway TLS certificate")

	// IDP intent avatar sync flags
	cmd.Flags().IntVar(&cfg.IdpIntentUserLookupAttempts, "idp-intent-user-lookup-attempts", cfg.IdpIntentUserLookupAttempts, "Retry count when idpintent.succeeded arrives before the Milo User exists")
	cmd.Flags().DurationVar(&cfg.IdpIntentUserLookupBaseWait, "idp-intent-user-lookup-base-wait", cfg.IdpIntentUserLookupBaseWait, "Initial backoff between idp-intent user lookup retries")

	// Zitadel flags
	cmd.Flags().StringVar(&zitadelIssuer, "zitadel-issuer", "", "Zitadel issuer URL (fallback: ZITADEL_ISSUER env)")
	cmd.Flags().StringVar(&zitadelAPI, "zitadel-api", "", "Zitadel API base URL (fallback: ZITADEL_API env)")
	cmd.Flags().StringVar(&zitadelKeyPath, "zitadel-key", "", "Path to Zitadel machine account key (fallback: ZITADEL_KEY_PATH env)")
	cmd.Flags().DurationVar(&defaultMachineKeyExpiration, "zitadel-default-machine-key-expiration", 10*365*24*time.Hour, "The default duration for machine account keys (defaults to 10 years)")

	return cmd
}

func createZitadelClient(
	ctx context.Context,
	issuer string,
	domain string,
	keyPath string,
	defaultExpiration time.Duration,
) (zitadel.API, error) {
	// Only read the key path from env if the flag is empty
	if keyPath == "" {
		keyPath = os.Getenv("ZITADEL_KEY_PATH")
	}
	if keyPath == "" {
		keyPath = os.Getenv("ZITADEL_MACHINE_ACCOUNT_KEY_PATH")
	}

	// Domain and Issuer must be provided via flags (do not fallback to environment)
	if issuer == "" || domain == "" || keyPath == "" {
		return nil, nil
	}

	return zitadel.NewSDK(ctx, zitadel.SDKConfig{
		Issuer:                      issuer,
		Domain:                      domain,
		KeyPath:                     keyPath,
		DefaultMachineKeyExpiration: defaultExpiration,
	})
}

// retryZitadelClient keeps attempting to initialize the Zitadel SDK client with
// exponential backoff until it succeeds (or the context is cancelled), then
// installs it on the server. This lets the server start and become Ready while
// Zitadel is still coming up, recovering from a same-pod startup race or a
// transient Zitadel outage without crash-looping.
func retryZitadelClient(
	ctx context.Context,
	log logr.Logger,
	svr *httpactionsserver.Server,
	issuer string,
	domain string,
	keyPath string,
	defaultExpiration time.Duration,
) {
	const (
		initialBackoff = 1 * time.Second
		maxBackoff     = 1 * time.Minute
	)

	backoff := initialBackoff
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		client, err := createZitadelClient(ctx, issuer, domain, keyPath, defaultExpiration)
		if err != nil {
			log.Error(err, "Retrying Zitadel SDK client initialization", "retryIn", backoff.String())
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		if client == nil {
			// Configuration is incomplete; nothing to retry.
			return
		}

		svr.SetZitadelClient(client)
		log.Info("Successfully initialized Zitadel SDK client (background retry)")
		return
	}
}
