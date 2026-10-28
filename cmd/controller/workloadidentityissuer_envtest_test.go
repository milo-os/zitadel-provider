package controller

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	mcbuilder "sigs.k8s.io/multicluster-runtime/pkg/builder"
	mccontroller "sigs.k8s.io/multicluster-runtime/pkg/controller"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	mcreconcile "sigs.k8s.io/multicluster-runtime/pkg/reconcile"
	mcsingle "sigs.k8s.io/multicluster-runtime/providers/single"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

// These tests run the multicluster manager as single mode runs it, against a real API server, with
// --enable-workload-identity-issuers on. Another controller on the same manager must keep reconciling either way.

func TestWorkloadIdentityIssuerControllersWithoutTheCRD(t *testing.T) {
	if registered := runSingleModeWithTheFlagOn(t, startTestAPIServer(t, nil)); registered {
		t.Fatal("the WorkloadIdentityIssuer controllers were set up although the kind is not served")
	}
}

func TestWorkloadIdentityIssuerControllersWithTheCRD(t *testing.T) {
	crds := []string{miloWorkloadIdentityIssuerCRD(t)}
	if registered := runSingleModeWithTheFlagOn(t, startTestAPIServer(t, crds)); !registered {
		t.Fatal("the WorkloadIdentityIssuer controllers were left out although the kind is served")
	}
}

// runSingleModeWithTheFlagOn sets the controllers up beside a probe controller, starts the manager, and waits until
// the probe reconciles a ConfigMap. It fails the test if the manager stops first. It reports whether the
// WorkloadIdentityIssuer controllers were set up.
func runSingleModeWithTheFlagOn(t *testing.T, cfg *rest.Config) bool {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := iamv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	deploymentCluster, err := cluster.New(cfg, func(o *cluster.Options) { o.Scheme = scheme })
	if err != nil {
		t.Fatal(err)
	}
	provider := &wrappedSingleClusterProvider{Provider: mcsingle.New("single", deploymentCluster), cluster: deploymentCluster}
	mgr, err := mcmanager.New(cfg, provider, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Fatal(err)
	}

	registered, err := setupWorkloadIdentityIssuerControllers(true, mgr, deploymentCluster.GetRESTMapper())
	if err != nil {
		t.Fatalf("setting up the WorkloadIdentityIssuer controllers: %v", err)
	}
	reconciled := make(chan struct{}, 1)
	// Both tests name a probe controller in one process, so its name is not checked for uniqueness.
	err = mcbuilder.ControllerManagedBy(mgr).Named("probe").For(&corev1.ConfigMap{}).
		WithOptions(mccontroller.Options{SkipNameValidation: ptr.To(true)}).
		Complete(mcreconcile.Func(func(_ context.Context, req mcreconcile.Request) (ctrl.Result, error) {
			if req.Name == "probe" {
				select {
				case reconciled <- struct{}{}:
				default:
				}
			}
			return ctrl.Result{}, nil
		}))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stopped := make(chan error, 2)
	go func() { stopped <- deploymentCluster.Start(ctx) }()
	go func() { stopped <- mgr.Start(ctx) }()

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	probe := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "probe", Namespace: "default"}}
	if err := c.Create(ctx, probe); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reconciled:
	case err := <-stopped:
		t.Fatalf("the manager stopped before the probe reconciled: %v", err)
	case <-time.After(time.Minute):
		t.Fatal("the probe controller never reconciled")
	}
	return registered
}

// startTestAPIServer starts an API server with the CRDs in crdPaths, and stops it when the test ends.
func startTestAPIServer(t *testing.T, crdPaths []string) *rest.Config {
	t.Helper()
	env := &envtest.Environment{CRDDirectoryPaths: crdPaths, ErrorIfCRDPathMissing: len(crdPaths) > 0}
	if dir := firstEnvtestBinaryDir(); dir != "" {
		env.BinaryAssetsDirectory = dir
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("starting the test API server: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	return cfg
}

// firstEnvtestBinaryDir finds the binaries `make setup-envtest` installs, so the tests also run from an IDE.
func firstEnvtestBinaryDir() string {
	base := filepath.Join("..", "..", "bin", "k8s")
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
