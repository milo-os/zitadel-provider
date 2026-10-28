package keyset

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	mcsingle "sigs.k8s.io/multicluster-runtime/providers/single"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

// TestControllerPublishesStatus runs the controller on a multicluster manager against a real API server with
// the WorkloadIdentityIssuer CRD, as single mode runs it. An inline issuer gets its status, and disabling it
// clears Ready.
func TestControllerPublishesStatus(t *testing.T) {
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{miloWorkloadIdentityIssuerCRD(t)},
		ErrorIfCRDPathMissing: true,
	}
	if dir := firstEnvtestBinaryDir(); dir != "" {
		env.BinaryAssetsDirectory = dir
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("starting the test API server: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })

	scheme := runtime.NewScheme()
	if err := iamv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cl, err := cluster.New(cfg, func(o *cluster.Options) { o.Scheme = scheme })
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := mcmanager.New(cfg, mcsingle.New("single", cl), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Controller{}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = cl.Start(ctx) }()
	go func() { _ = mgr.Start(ctx) }()

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	encKey := `{"kty":"OKP","crv":"Ed25519","kid":"k3","use":"enc","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	issuer := inlineIssuer(`{"keys":[` + edKey + `,` + ecKey + `,` + encKey + `]}`)
	issuer.Generation = 0
	issuer.Spec.RequiredClaims = map[string]iamv1alpha1.ClaimValue{"env": "prod"}
	issuer.Spec.MaxTokenLifetime = &metav1.Duration{Duration: 30 * time.Minute}
	if err := c.Create(ctx, issuer); err != nil {
		t.Fatal(err)
	}

	got := waitForStatus(t, c, issuer.Name, func(i *iamv1alpha1.WorkloadIdentityIssuer) bool {
		return i.Status.ObservedGeneration == i.Generation && meta.IsStatusConditionTrue(i.Status.Conditions, "Ready")
	})
	s := got.Status
	if r := meta.FindStatusCondition(s.Conditions, "Ready"); r.Reason != "KeysDropped" {
		t.Fatalf("Ready's reason = %s; want KeysDropped, for the encryption key", r.Reason)
	}
	var keySet struct{ Keys []json.RawMessage }
	if err := json.Unmarshal([]byte(s.KeySet), &keySet); err != nil || len(keySet.Keys) != 2 {
		t.Fatalf("status.keySet = %s; want the two signing keys", s.KeySet)
	}
	if s.Issuer != "https://idp.example.com" || s.KeySetGeneration != 1 || s.MaxTokenLifetime.Duration != 30*time.Minute ||
		s.RequiredClaims["env"] != "prod" || s.LastFetchTime == nil {
		t.Fatalf("status = %+v", s)
	}

	got.Spec.Disabled = true
	if err := c.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	disabled := waitForStatus(t, c, issuer.Name, func(i *iamv1alpha1.WorkloadIdentityIssuer) bool {
		return i.Status.ObservedGeneration == i.Generation && meta.IsStatusConditionTrue(i.Status.Conditions, "Disabled")
	})
	if r := meta.FindStatusCondition(disabled.Status.Conditions, "Ready"); r.Status != metav1.ConditionFalse || r.Reason != "Disabled" {
		t.Fatalf("Ready after disabling = %+v; want False, Disabled", r)
	}
}

// waitForStatus reads the issuer until done holds, for up to a minute.
func waitForStatus(t *testing.T, c client.Client, name string,
	done func(*iamv1alpha1.WorkloadIdentityIssuer) bool) *iamv1alpha1.WorkloadIdentityIssuer {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		got := &iamv1alpha1.WorkloadIdentityIssuer{}
		if err := c.Get(context.Background(), client.ObjectKey{Name: name}, got); err == nil && done(got) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("issuer %s: status never reached the expected state: %+v", name, got.Status)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// firstEnvtestBinaryDir finds the binaries `make setup-envtest` installs, so the test also runs from an IDE.
func firstEnvtestBinaryDir() string {
	base := filepath.Join("..", "..", "..", "bin", "k8s")
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(base, entry.Name())
		}
	}
	return ""
}

// miloWorkloadIdentityIssuerCRD returns the path of the WorkloadIdentityIssuer CRD in the Milo module this module
// builds against, which defines the kind.
func miloWorkloadIdentityIssuerCRD(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "go.miloapis.com/milo").Output()
	dir := strings.TrimSpace(string(out))
	if err != nil || dir == "" {
		t.Fatalf("finding the Milo module (run go mod download): %v", err)
	}
	return filepath.Join(dir, "config", "crd", "bases", "iam", "iam.miloapis.com_workloadidentityissuers.yaml")
}
