package webhookserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"

	"go.miloapis.com/auth-provider-zitadel/internal/config"
	webhook "go.miloapis.com/auth-provider-zitadel/internal/webhook"
)

// recordingRegistrar stands in for controller-runtime's webhook server. Endpoint
// registration is the only thing runWebhookServer does with it, so a test can watch
// exactly which routes a configuration produces without a cluster.
type recordingRegistrar struct {
	paths []string
}

func (r *recordingRegistrar) Register(path string, _ http.Handler) {
	r.paths = append(r.paths, path)
}

func (r *recordingRegistrar) has(path string) bool {
	for _, p := range r.paths {
		if p == path {
			return true
		}
	}
	return false
}

// capturingSink records what registerEndpoints logged. A disabled recovery endpoint
// is only safe if an operator can find out why from the logs, so the message is part
// of the behaviour under test, not incidental output.
type capturingSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *capturingSink) Init(logr.RuntimeInfo) {}
func (s *capturingSink) Enabled(int) bool      { return true }

func (s *capturingSink) Info(_ int, msg string, kv ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, fmt.Sprintf("%s | %v", msg, kv))
}

func (s *capturingSink) Error(err error, msg string, kv ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, fmt.Sprintf("ERROR | %v | %s | %v", err, msg, kv))
}

func (s *capturingSink) WithValues(...any) logr.LogSink { return s }
func (s *capturingSink) WithName(string) logr.LogSink   { return s }

func (s *capturingSink) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

// stubMinter is the Zitadel client the recovery endpoint would mint codes with. It
// is never called here: these tests are about whether the endpoint gets registered.
type stubMinter struct{}

func (stubMinter) CreatePasskeyRegistrationLink(context.Context, string) (string, string, error) {
	return "", "", errors.New("not called in these tests")
}

// recoveryConfig is a configuration with recovery and verification both switched on,
// which is the shape the incident happened in.
func recoveryConfig(t *testing.T, serviceAccountKey string) *config.WebhookServerConfig {
	t.Helper()
	cfg := config.NewWebhookServerConfig()
	cfg.ZitadelDomain = "https://auth.example.test"
	cfg.ZitadelPrivateKey = writeKey(t, "application-key.json", fixtureApplicationKey)
	cfg.ZitadelServiceAccountKey = serviceAccountKey
	cfg.ClientCAFile = "ca.crt"
	cfg.EmailVerificationTemplate = "verify-tpl"
	cfg.AccountRecoveryTemplate = "recovery-tpl"
	return cfg
}

func runRegister(t *testing.T, cfg *config.WebhookServerConfig, deps webhookDeps) (*recordingRegistrar, string) {
	t.Helper()
	reg := &recordingRegistrar{}
	sink := &capturingSink{}
	registerEndpoints(context.Background(), reg, logr.New(sink), cfg, deps)
	return reg, sink.text()
}

// realDeps uses the production minter builder. The failure paths below all refuse
// before the SDK would dial anything, so exercising them this way tests the real
// wiring rather than a test double of it.
func realDeps() webhookDeps {
	return webhookDeps{newMinter: newRecoveryMinter}
}

// The rule this whole change exists to enforce: nothing about account recovery may
// stop the webhook from serving TokenReview. Every way the recovery client can fail
// to be built must leave the process up with the other two endpoints registered.
func TestRegisterEndpoints_RecoveryFailuresNeverStopTheServer(t *testing.T) {
	for name, tc := range map[string]struct {
		deps func(t *testing.T) (webhookDeps, string) // deps, service-account key path
		// wantLogContains is the operator-facing diagnosis. Each failure has to
		// name the flag, not just complain.
		wantLogContains []string
	}{
		"no service account key configured at all": {
			deps: func(*testing.T) (webhookDeps, string) { return realDeps(), "" },
			wantLogContains: []string{
				"--zitadel-service-account-key",
				"Account recovery endpoint disabled",
			},
		},
		"the key file was never mounted": {
			deps: func(t *testing.T) (webhookDeps, string) {
				return realDeps(), writeKey(t, "present.json", fixtureServiceAccountKey) + ".missing"
			},
			wantLogContains: []string{
				"--zitadel-service-account-key",
				"Account recovery endpoint disabled",
			},
		},
		"the introspection application key was mounted by mistake": {
			deps: func(t *testing.T) (webhookDeps, string) {
				return realDeps(), writeKey(t, "machine-account-key.json", fixtureApplicationKey)
			},
			wantLogContains: []string{
				"APPLICATION key",
				"iam-admin",
				"zitadel-machine-auth-api-key",
				"Account recovery endpoint disabled",
			},
		},
		"the key file is not JSON": {
			deps: func(t *testing.T) (webhookDeps, string) {
				return realDeps(), writeKey(t, "key.json", "not json at all")
			},
			wantLogContains: []string{
				"--zitadel-service-account-key",
				"Account recovery endpoint disabled",
			},
		},
		"the Zitadel SDK refuses to build a client": {
			deps: func(t *testing.T) (webhookDeps, string) {
				deps := webhookDeps{
					newMinter: func(context.Context, *config.WebhookServerConfig) (passkeyCodeMinter, error) {
						return nil, errors.New("issuer must include scheme (e.g. https://auth.example.com)")
					},
				}
				return deps, writeKey(t, "service-account-key.json", fixtureServiceAccountKey)
			},
			wantLogContains: []string{
				"issuer must include scheme",
				"Account recovery endpoint disabled",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			deps, keyPath := tc.deps(t)
			cfg := recoveryConfig(t, keyPath)

			reg, logged := runRegister(t, cfg, deps)

			// The whole point: the server is still serving.
			if !reg.has(tokenReviewEndpoint) {
				t.Errorf("TokenReview endpoint must stay registered, got routes: %v", reg.paths)
			}
			if !reg.has(webhook.EmailVerificationEndpoint) {
				t.Errorf("email verification endpoint must stay registered, got routes: %v", reg.paths)
			}
			// And the broken endpoint is simply absent.
			if reg.has(webhook.AccountRecoveryEndpoint) {
				t.Errorf("recovery endpoint must NOT be registered when its client could not be built, got routes: %v", reg.paths)
			}
			for _, want := range tc.wantLogContains {
				if !strings.Contains(logged, want) {
					t.Errorf("log should mention %q so an operator can fix it, got:\n%s", want, logged)
				}
			}
		})
	}
}

// The happy path still has to work: a real service account key registers recovery
// alongside everything else.
func TestRegisterEndpoints_ValidServiceAccountKeyRegistersRecovery(t *testing.T) {
	cfg := recoveryConfig(t, writeKey(t, "service-account-key.json", fixtureServiceAccountKey))
	deps := webhookDeps{
		newMinter: func(context.Context, *config.WebhookServerConfig) (passkeyCodeMinter, error) {
			return stubMinter{}, nil
		},
	}

	reg, _ := runRegister(t, cfg, deps)

	for _, want := range []string{
		tokenReviewEndpoint,
		webhook.EmailVerificationEndpoint,
		webhook.AccountRecoveryEndpoint,
	} {
		if !reg.has(want) {
			t.Errorf("expected %s to be registered, got routes: %v", want, reg.paths)
		}
	}
}

// An unconfigured recovery endpoint is not a failure and must not be logged as one:
// an empty template is how every deployment that does not want recovery is spelled.
func TestRegisterEndpoints_NoTemplateIsNotAnError(t *testing.T) {
	cfg := recoveryConfig(t, "")
	cfg.AccountRecoveryTemplate = ""

	reg, logged := runRegister(t, cfg, realDeps())

	if reg.has(webhook.AccountRecoveryEndpoint) {
		t.Errorf("recovery must not be registered without a template, got routes: %v", reg.paths)
	}
	if !reg.has(tokenReviewEndpoint) {
		t.Errorf("TokenReview endpoint must be registered, got routes: %v", reg.paths)
	}
	if strings.Contains(logged, "ERROR") {
		t.Errorf("an unconfigured endpoint is not an error, got:\n%s", logged)
	}
}

// The service account key is only consulted when recovery is switched on. A cluster
// that does not use recovery must not be made to mount a key it has no use for.
func TestRegisterEndpoints_ServiceAccountKeyIrrelevantWithoutRecovery(t *testing.T) {
	cfg := recoveryConfig(t, writeKey(t, "machine-account-key.json", fixtureApplicationKey))
	cfg.AccountRecoveryTemplate = ""

	_, logged := runRegister(t, cfg, realDeps())

	if strings.Contains(logged, "APPLICATION key") {
		t.Errorf("an unused key must not be validated or complained about, got:\n%s", logged)
	}
}

// tokenReviewEndpoint is spelled out in this package so the tests above can assert
// the route the cluster depends on is still there. The handler owns the real value,
// so pin the two together rather than let them drift apart silently.
func TestTokenReviewEndpointMatchesTheHandler(t *testing.T) {
	if got := webhook.NewAuthenticationWebhookV1(nil).Endpoint; got != tokenReviewEndpoint {
		t.Fatalf("tokenReviewEndpoint is %q but the handler registers %q", tokenReviewEndpoint, got)
	}
}
