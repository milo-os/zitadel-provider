package webhookserver

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	"go.miloapis.com/auth-provider-zitadel/internal/config"
)

type recordedReadyz struct {
	name  string
	check healthz.Checker
}

func (r *recordedReadyz) AddReadyzCheck(name string, check healthz.Checker) error {
	r.name, r.check = name, check
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
	rec := &recordedReadyz{}

	if err := addReadiness(rec, server); err != nil {
		t.Fatalf("addReadiness: %v", err)
	}
	if rec.name != "webhook" || rec.check == nil {
		t.Fatalf("no readiness check on the webhook server: %+v", rec)
	}
	if err := rec.check(nil); err == nil {
		t.Errorf("ready before the webhook server serves")
	}
}
