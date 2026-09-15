package zitadelapiserver

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/apis/apiserver"
	authorizerfactory "k8s.io/apiserver/pkg/authorization/authorizerfactory"
	openapi "k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/registry/rest"
	genericserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	authzv1client "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/tools/clientcmd"
	compatibility "k8s.io/component-base/compatibility"
	"k8s.io/klog/v2"
	openapicommon "k8s.io/kube-openapi/pkg/common"
	generatedopenapi "k8s.io/kubernetes/pkg/generated/openapi"

	registrypasskeyregistrationlinks "go.miloapis.com/auth-provider-zitadel/internal/apiserver/identity/passkeyregistrationlinks"
	registrypasskeys "go.miloapis.com/auth-provider-zitadel/internal/apiserver/identity/passkeys"
	registryserviceaccountkeys "go.miloapis.com/auth-provider-zitadel/internal/apiserver/identity/serviceaccountkeys"
	registrysessions "go.miloapis.com/auth-provider-zitadel/internal/apiserver/identity/sessions"
	registryuseridentities "go.miloapis.com/auth-provider-zitadel/internal/apiserver/identity/useridentities"
	"go.miloapis.com/auth-provider-zitadel/internal/config"
	identityinstall "go.miloapis.com/auth-provider-zitadel/pkg/apis/identity"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	miloidentity "go.miloapis.com/milo/pkg/apis/identity"
	identityv1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// NewAPIServerCommand creates a cobra command that runs the aggregated API server
// for the identity.miloapis.com/v1alpha1 group.
func NewAPIServerCommand(global *config.GlobalConfig) *cobra.Command {
	log := logf.Log.WithName("apiserver-cmd")

	var (
		tlsCertFile string
		tlsKeyFile  string
		securePort  int
		// RequestHeader front-proxy trust configuration
		requestHeaderCAFile           string
		requestHeaderAllowedNames     []string
		requestHeaderUsernameHeaders  []string
		requestHeaderGroupHeaders     []string
		requestHeaderUIDHeaders       []string
		requestHeaderExtraHeadersPref []string
		// Zitadel configuration (flags with env fallbacks)
		zitadelIssuer                    string
		zitadelAPI                       string
		zitadelKeyPath                   string
		zitadelDefaultMachineKeyExpirary time.Duration
		zitadelIntrospectionProjectID    string
		// Local testing override
		enableImpersonationFallback bool
		// Account recovery (admin backstop, Phase C)
		recoveryLinksEnabled           bool
		accountRecoverySupportTemplate string
		accountRecoveryCompleteURL     string
		accountRecoveryExpiryMinutes   int
		notificationNamespace          string
	)

	cmd := &cobra.Command{
		Use:   "apiserver",
		Short: "Run API server for Zitadel sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := config.InitializeLogging(global); err != nil {
				return fmt.Errorf("init logging: %w", err)
			}
			// Route klog through the controller-runtime logger and ensure flushing on exit
			klog.EnableContextualLogging(true)
			defer klog.Flush()
			log.Info("Starting API server")

			scheme := runtime.NewScheme()
			identityinstall.Install(scheme)
			miloidentity.Install(scheme)
			_ = clientgoscheme.AddToScheme(scheme)

			codecs := serializer.NewCodecFactory(scheme)

			ro := genericoptions.NewRecommendedOptions("/unused/registry", nil)
			// Ensure we don't try to bind to privileged port 443; default to 8443 and allow override via flag
			ro.SecureServing.BindPort = securePort
			if tlsCertFile != "" && tlsKeyFile != "" {
				ro.SecureServing.ServerCert.CertKey.CertFile = tlsCertFile
				ro.SecureServing.ServerCert.CertKey.KeyFile = tlsKeyFile
			}
			// Configure RequestHeader authn to trust Milo as a front-proxy
			authn := genericoptions.NewDelegatingAuthenticationOptions()
			authn.SkipInClusterLookup = true
			authn.Anonymous = &apiserver.AnonymousAuthConfig{Enabled: false}
			authn.RequestHeader.ClientCAFile = requestHeaderCAFile
			authn.RequestHeader.AllowedNames = requestHeaderAllowedNames
			authn.RequestHeader.UsernameHeaders = requestHeaderUsernameHeaders
			authn.RequestHeader.GroupHeaders = requestHeaderGroupHeaders
			authn.RequestHeader.UIDHeaders = requestHeaderUIDHeaders
			authn.RequestHeader.ExtraHeaderPrefixes = requestHeaderExtraHeadersPref
			ro.Authentication = authn
			// Use an allow-all authorizer so Milo acts as PDP
			ro.Authorization = nil
			ro.Etcd = nil
			ro.Admission = nil
			ro.CoreAPI = nil
			ro.Audit = nil
			ro.Features.EnablePriorityAndFairness = false

			cfg := genericserver.NewRecommendedConfig(codecs)
			if err := ro.ApplyTo(cfg); err != nil {
				return fmt.Errorf("apply recommended options: %w", err)
			}

			// Always-allow authorizer (treat Milo front-proxy as PDP)
			cfg.Authorization.Authorizer = authorizerfactory.NewAlwaysAllowAuthorizer()
			// Ensure EffectiveVersion is non-nil to avoid nil deref in Complete()
			if cfg.EffectiveVersion == nil {
				cfg.EffectiveVersion = compatibility.NewEffectiveVersionFromString("", "", "")
			}
			// Enable OpenAPI and provide minimal definitions set
			cfg.SkipOpenAPIInstallation = false
			getOpenAPIDefinitions := func(ref openapicommon.ReferenceCallback) map[string]openapicommon.OpenAPIDefinition {
				base := generatedopenapi.GetOpenAPIDefinitions(ref)
				id := identityv1alpha1.GetOpenAPIDefinitions(ref)
				for k, v := range id {
					base[k] = v
				}
				return base
			}
			cfg.OpenAPIConfig = genericserver.DefaultOpenAPIConfig(getOpenAPIDefinitions, openapi.NewDefinitionNamer(scheme))
			cfg.OpenAPIConfig.Info.Title = "Milo Identity API"
			cfg.OpenAPIConfig.Info.Version = "v1alpha1"
			cfg.OpenAPIV3Config = genericserver.DefaultOpenAPIV3Config(getOpenAPIDefinitions, openapi.NewDefinitionNamer(scheme))

			// Note: secure serving is configured by flags of the apiserver library; we default to its settings.

			srv, err := cfg.Complete().New("zitadel-sessions-apiserver", genericserver.NewEmptyDelegate())
			if err != nil {
				return fmt.Errorf("build server: %w", err)
			}

			zc, err := zitadel.NewSDK(context.Background(), zitadel.SDKConfig{
				Issuer:                      zitadelIssuer,
				Domain:                      zitadelAPI,
				KeyPath:                     zitadelKeyPath,
				DefaultMachineKeyExpiration: zitadelDefaultMachineKeyExpirary,
			})
			if err != nil {
				return fmt.Errorf("init zitadel sdk: %w", err)
			}

			// Optional: build a SubjectAccessReviews client against milo
			// for cross-user identity/session lookups. Loaded via the
			// standard kube client config (KUBECONFIG env / --kubeconfig
			// flag / in-cluster fallback) — same pattern the sibling
			// authn-webhook Deployment uses (it sets KUBECONFIG to the
			// milo kubeconfig path on the pod). If the loader can't find
			// a valid config, we leave miloSAR nil and the REST handlers
			// reject cross-user lookups with a clear error; self-only
			// lookups still work.
			var miloSAR authzv1client.SubjectAccessReviewInterface
			restCfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
				clientcmd.NewDefaultClientConfigLoadingRules(),
				&clientcmd.ConfigOverrides{},
			).ClientConfig()
			if err != nil {
				log.Info("No kube client config found for milo SAR; cross-user identity/session lookups disabled", "reason", err.Error())
			} else {
				clientset, err := kubernetes.NewForConfig(restCfg)
				if err != nil {
					return fmt.Errorf("build milo clientset from kube client config: %w", err)
				}
				miloSAR = clientset.AuthorizationV1().SubjectAccessReviews()
				log.Info("Cross-user identity/session lookups enabled via milo SAR", "host", restCfg.Host)
			}

			// Uncached client to the core control plane: the recovery resource reads
			// one User and creates one Email per request. It shares the kube client
			// config the SAR client above was built from.
			var miloClient ctrlclient.Client
			if restCfg != nil {
				miloScheme := runtime.NewScheme()
				if err := iamv1alpha1.AddToScheme(miloScheme); err != nil {
					return fmt.Errorf("add iam types to milo scheme: %w", err)
				}
				if err := notificationv1alpha1.AddToScheme(miloScheme); err != nil {
					return fmt.Errorf("add notification types to milo scheme: %w", err)
				}
				miloClient, err = ctrlclient.New(restCfg, ctrlclient.Options{Scheme: miloScheme})
				if err != nil {
					return fmt.Errorf("build milo client: %w", err)
				}
			}

			passkeyRegistrationLinks, err := registrypasskeyregistrationlinks.New(registrypasskeyregistrationlinks.Options{
				Z:                     zc,
				Milo:                  miloClient,
				MiloSAR:               miloSAR,
				Enabled:               recoveryLinksEnabled,
				SupportTemplateName:   accountRecoverySupportTemplate,
				NotificationNamespace: notificationNamespace,
				CompleteURL:           accountRecoveryCompleteURL,
				ExpiryMinutes:         accountRecoveryExpiryMinutes,
			})
			if err != nil {
				return fmt.Errorf("init passkeyregistrationlinks storage: %w", err)
			}

			storage := map[string]rest.Storage{
				"sessions":       &registrysessions.REST{Z: zc, MiloSAR: miloSAR},
				"useridentities": &registryuseridentities.REST{Z: zc, MiloSAR: miloSAR},
				"passkeys":       &registrypasskeys.REST{Z: zc, MiloSAR: miloSAR},
				"serviceaccountkeys": &registryserviceaccountkeys.REST{
					Z:                           zc,
					EnableImpersonationFallback: enableImpersonationFallback,
					IntrospectionProjectID:      zitadelIntrospectionProjectID,
				},
				"passkeyregistrationlinks": passkeyRegistrationLinks,
			}

			agi := genericserver.NewDefaultAPIGroupInfo(identityv1alpha1.SchemeGroupVersion.Group, scheme, metav1.ParameterCodec, codecs)
			agi.VersionedResourcesStorageMap = map[string]map[string]rest.Storage{"v1alpha1": storage}
			if err := srv.InstallAPIGroup(&agi); err != nil {
				return fmt.Errorf("install api group: %w", err)
			}

			log.Info("API server is starting")
			return srv.PrepareRun().RunWithContext(cmd.Context())
		},
	}

	cmd.Flags().StringVar(&tlsCertFile, "tls-cert-file", "", "Path to TLS certificate")
	cmd.Flags().StringVar(&tlsKeyFile, "tls-private-key-file", "", "Path to TLS private key")
	cmd.Flags().IntVar(&securePort, "secure-port", 8443, "Secure serving port")
	// RequestHeader trust configuration flags
	cmd.Flags().StringVar(&requestHeaderCAFile, "requestheader-client-ca-file", "", "Path to PEM CA bundle that signs Milo's proxy client cert")
	cmd.Flags().StringSliceVar(&requestHeaderAllowedNames, "requestheader-allowed-names", nil, "Allowed CNs for Milo proxy client cert; empty means any signed by CA")
	cmd.Flags().StringSliceVar(&requestHeaderUsernameHeaders, "requestheader-username-headers", nil, "Header names to determine user identity")
	cmd.Flags().StringSliceVar(&requestHeaderGroupHeaders, "requestheader-group-headers", nil, "Header names to determine user groups")
	cmd.Flags().StringSliceVar(&requestHeaderUIDHeaders, "requestheader-uid-headers", nil, "Header names to determine user UID")
	cmd.Flags().StringSliceVar(&requestHeaderExtraHeadersPref, "requestheader-extra-headers-prefix", nil, "Header name prefixes to determine user extra info")
	cmd.Flags().StringVar(&zitadelIssuer, "zitadel-issuer", "", "Zitadel issuer URL")
	cmd.Flags().StringVar(&zitadelAPI, "zitadel-api", "", "Zitadel API base URL")
	cmd.Flags().StringVar(&zitadelKeyPath, "zitadel-key", "", "Path to Zitadel machine account key")
	cmd.Flags().DurationVar(&zitadelDefaultMachineKeyExpirary, "zitadel-default-machine-key-expiration", 10*365*24*time.Hour, "The default duration for machine account keys (defaults to 10 years)")
	// Account recovery (admin backstop). --recovery-links-enabled is the infra-owned
	// switch: while false the create returns 503, so the milo role can ship dormant.
	cmd.Flags().BoolVar(&recoveryLinksEnabled, "recovery-links-enabled", false,
		"Enable the PasskeyRegistrationLink create; while false the endpoint returns 503")
	cmd.Flags().StringVar(&accountRecoverySupportTemplate, "account-recovery-support-template", "",
		"EmailTemplate resource for support-triggered account recovery mail")
	cmd.Flags().StringVar(&accountRecoveryCompleteURL, "account-recovery-complete-url", "",
		"Landing URL for the mailed recovery link, e.g. https://auth.datum.net/recover/complete")
	cmd.Flags().IntVar(&accountRecoveryExpiryMinutes, "account-recovery-expiry-minutes", 60,
		"Recovery code lifetime shown to users; must match Zitadel's PasswordlessInitCode lifetime")
	cmd.Flags().StringVar(&notificationNamespace, "notification-namespace", "milo-system",
		"Namespace in which Email resources are created")

	cmd.Flags().StringVar(&zitadelIntrospectionProjectID, "zitadel-introspection-project-id", "", "Numeric Zitadel project ID (e.g. 326089123456789012) that the authn webhook's introspection client is a member of. When set, generated machine account credentials include an audience scope for this project so their tokens can be introspected. Leave empty to preserve prior behavior.")
	cmd.Flags().BoolVar(&enableImpersonationFallback, "enable-impersonation-fallback", false, "Enable looking up project ID from k8s impersonation extras (for local testing without Milo proxy)")

	// Wire klog flags to this command so users can set verbosity with -v=N
	goFS := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(goFS)
	cmd.Flags().AddGoFlagSet(goFS)

	return cmd
}
