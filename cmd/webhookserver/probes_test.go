package webhookserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	"go.miloapis.com/auth-provider-zitadel/internal/config"
)

type recordedProbes struct {
	readyz  map[string]healthz.Checker
	healthz map[string]healthz.Checker
}

func newRecordedProbes() *recordedProbes {
	return &recordedProbes{readyz: map[string]healthz.Checker{}, healthz: map[string]healthz.Checker{}}
}

func (r *recordedProbes) AddReadyzCheck(name string, check healthz.Checker) error {
	r.readyz[name] = check
	return nil
}

func (r *recordedProbes) AddHealthzCheck(name string, check healthz.Checker) error {
	r.healthz[name] = check
	return nil
}

func TestManagerOptionsServeTheProbeEndpoint(t *testing.T) {
	cfg := config.NewWebhookServerConfig()
	cfg.HealthProbeBindAddress = ":8081"

	opts := managerOptions(cfg, runtime.NewScheme())

	if opts.HealthProbeBindAddress != ":8081" {
		t.Errorf("the manager serves no probe endpoint: HealthProbeBindAddress %q", opts.HealthProbeBindAddress)
	}
	if opts.WebhookServer == nil {
		t.Errorf("the manager has no webhook server")
	}
}

func TestReadinessWaitsForTheWebhookServer(t *testing.T) {
	server := ctrlwebhook.NewServer(ctrlwebhook.Options{Port: 9443})
	rec := newRecordedProbes()

	if err := addProbes(rec, server); err != nil {
		t.Fatalf("addProbes: %v", err)
	}
	check := rec.readyz["webhook"]
	if check == nil {
		t.Fatalf("no readiness check on the webhook server: %+v", rec.readyz)
	}
	if err := check(nil); err == nil {
		t.Errorf("ready before the webhook server serves")
	}
}

func TestLivenessAnswersWhileTheProcessRuns(t *testing.T) {
	server := ctrlwebhook.NewServer(ctrlwebhook.Options{Port: 9443})
	rec := newRecordedProbes()

	if err := addProbes(rec, server); err != nil {
		t.Fatalf("addProbes: %v", err)
	}
	if len(rec.healthz) == 0 {
		t.Fatal("no liveness check: the manager's /healthz answers 404")
	}

	handler := &healthz.Handler{Checks: rec.healthz}
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/", nil))
	if resp.Code != http.StatusOK {
		t.Errorf("/healthz answered %d before the webhook server serves; liveness must not wait on it", resp.Code)
	}
}
