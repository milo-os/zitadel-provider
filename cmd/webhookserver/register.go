package webhookserver

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.miloapis.com/auth-provider-zitadel/internal/config"
	webhook "go.miloapis.com/auth-provider-zitadel/internal/webhook"
	token "go.miloapis.com/auth-provider-zitadel/pkg/token"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
)

// tokenReviewEndpoint is the path the Kubernetes apiserver posts TokenReviews to.
// It is the reason this process exists; everything else here is additional.
const tokenReviewEndpoint = "/apis/authentication.k8s.io/v1/tokenreviews"

// endpointRegistrar is the slice of controller-runtime's webhook server that
// endpoint wiring uses. Declared narrow so registerEndpoints can be tested without
// a cluster — the same reason validateWebhookConfig is a free function.
type endpointRegistrar interface {
	Register(path string, hook http.Handler)
}

// passkeyCodeMinter is the one Zitadel call the recovery endpoint makes. Declared
// here as well as in the webhook package so this file can name the type it builds
// without exporting the webhook package's own; *zitadel.SDKClient satisfies both.
type passkeyCodeMinter interface {
	CreatePasskeyRegistrationLink(ctx context.Context, userID string) (codeID, code string, err error)
}

// webhookDeps are the collaborators the endpoints are built from, grouped so
// registerEndpoints keeps a signature a test can fill in.
type webhookDeps struct {
	introspector   *token.Introspector
	directClient   client.Client
	allowedClients []string
	// newMinter builds the Zitadel client the recovery endpoint mints codes with.
	// A field rather than a direct call so a test can reach the registration paths
	// without dialing Zitadel.
	newMinter func(context.Context, *config.WebhookServerConfig) (passkeyCodeMinter, error)
}

// newRecoveryMinter builds the recovery endpoint's Zitadel client.
//
// The credential is --zitadel-service-account-key, NOT --zitadel-private-key: the
// SDK mints a JWT-profile assertion for a service USER, while the introspector's key
// identifies an application. The key's shape is checked here rather than left to
// Zitadel, which answers a mismatch with an opaque "Errors.Internal".
func newRecoveryMinter(ctx context.Context, cfg *config.WebhookServerConfig) (passkeyCodeMinter, error) {
	if cfg.ZitadelServiceAccountKey == "" {
		return nil, fmt.Errorf("--zitadel-service-account-key is empty but --account-recovery-template is set: " +
			"the recovery endpoint calls the Zitadel API as a service user, which --zitadel-private-key " +
			"(the application key used for token introspection) cannot do. " +
			"Set --zitadel-service-account-key to a mounted Zitadel service account key JSON, " +
			"or clear --account-recovery-template to turn recovery off deliberately")
	}
	if err := validateServiceAccountKey(cfg.ZitadelServiceAccountKey); err != nil {
		return nil, err
	}
	// NewSDK strips the scheme off Domain.
	return zitadel.NewSDK(ctx, zitadel.SDKConfig{
		Domain:  cfg.ZitadelDomain,
		Issuer:  cfg.ZitadelDomain,
		KeyPath: cfg.ZitadelServiceAccountKey,
	})
}

// registerEndpoints wires up every route this server offers.
//
// It CANNOT fail. TokenReview is the apiserver's authentication path for the whole
// cluster, and the mail endpoints are conveniences bolted onto the same process; a
// misconfigured convenience must never be able to stop the process that answers
// TokenReview. On 2026-09-22 one did: a recovery client built from the wrong Zitadel
// key returned an error, the error was returned from startup, and
// /apis/authentication.k8s.io/v1/tokenreviews was down for ~9.5 minutes.
//
// So every recovery failure here logs at error level, leaves the route unregistered
// and returns. The configuration that would expose a mail endpoint to unauthenticated
// callers is still a hard startup failure — that check lives in validateWebhookConfig
// and is deliberately left alone, because serving is worse than not serving.
func registerEndpoints(
	ctx context.Context,
	reg endpointRegistrar,
	log logr.Logger,
	cfg *config.WebhookServerConfig,
	deps webhookDeps,
) {
	webhookv1 := webhook.NewAuthenticationWebhookV1(deps.introspector)
	reg.Register(webhookv1.Endpoint, webhookv1)

	if cfg.EmailVerificationTemplate != "" {
		verify := webhook.NewEmailVerificationHandler(deps.directClient, webhook.EmailVerificationConfig{
			TemplateName:          cfg.EmailVerificationTemplate,
			NotificationNamespace: cfg.NotificationNamespace,
			AllowedOrigins:        cfg.EmailVerificationAllowedOrigins,
			AllowedClientNames:    deps.allowedClients,
			ExpiryMinutes:         cfg.EmailVerificationExpiryMinutes,
			UserLookupAttempts:    cfg.EmailVerificationUserLookupAttempts,
			UserLookupBaseWait:    cfg.EmailVerificationUserLookupBaseWait,
		})
		reg.Register(verify.Endpoint, verify)
		log.Info("Registered email verification endpoint",
			"endpoint", verify.Endpoint,
			"allowedOrigins", cfg.EmailVerificationAllowedOrigins,
			"allowedClientNames", deps.allowedClients)
	} else {
		log.Info("Email verification endpoint disabled; no template configured")
	}

	if cfg.AccountRecoveryTemplate == "" {
		log.Info("Account recovery endpoint disabled; no template configured")
		return
	}

	// The recovery endpoint mints the code itself rather than relaying one the caller
	// supplied, so it needs a Zitadel client. If that client cannot be built, recovery
	// is the only thing that stops working.
	minter, err := deps.newMinter(ctx, cfg)
	if err != nil {
		log.Error(err, "Account recovery endpoint disabled; its Zitadel client could not be built. "+
			"TokenReview and email verification are unaffected and the server is still serving; "+
			"fix the flag named in the error and restart to enable recovery")
		return
	}

	recovery := webhook.NewAccountRecoveryHandler(deps.directClient, minter, webhook.AccountRecoveryConfig{
		TemplateName:          cfg.AccountRecoveryTemplate,
		NotificationNamespace: cfg.NotificationNamespace,
		AllowedOrigins:        cfg.AccountRecoveryAllowedOrigins,
		AllowedClientNames:    deps.allowedClients,
		ExpiryMinutes:         cfg.AccountRecoveryExpiryMinutes,
		Cooldown:              cfg.AccountRecoveryCooldown,
		MaxPerHour:            cfg.AccountRecoveryMaxPerHour,
		// Shared with verification: both race the same provisioning path.
		UserLookupAttempts: cfg.EmailVerificationUserLookupAttempts,
		UserLookupBaseWait: cfg.EmailVerificationUserLookupBaseWait,
	})
	reg.Register(recovery.Endpoint, recovery)
	log.Info("Registered account recovery endpoint",
		"endpoint", recovery.Endpoint,
		"allowedOrigins", cfg.AccountRecoveryAllowedOrigins,
		"allowedClientNames", deps.allowedClients)
}
