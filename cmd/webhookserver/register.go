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
const tokenReviewEndpoint = "/apis/authentication.k8s.io/v1/tokenreviews"

// endpointRegistrar is the part of controller-runtime's webhook server that
// registerEndpoints uses.
type endpointRegistrar interface {
	Register(path string, hook http.Handler)
}

// passkeyCodeMinter is the one Zitadel call the recovery endpoint makes.
type passkeyCodeMinter interface {
	CreatePasskeyRegistrationLink(ctx context.Context, userID string) (codeID, code string, err error)
}

// webhookDeps are the collaborators the endpoints are built from.
type webhookDeps struct {
	introspector   *token.Introspector
	directClient   client.Client
	allowedClients []string
	newMinter      func(context.Context, *config.WebhookServerConfig) (passkeyCodeMinter, error)
}

// newRecoveryMinter builds the recovery endpoint's Zitadel client from the service
// account key; the application key in --zitadel-private-key cannot mint its JWT.
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

// registerEndpoints wires up every route. It must not fail: a recovery endpoint that
// cannot be built is logged and left unregistered so TokenReview keeps serving.
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
