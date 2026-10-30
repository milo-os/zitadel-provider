package controller

import (
	"errors"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"go.miloapis.com/auth-provider-zitadel/internal/config"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

func TestWorkloadIdentityIssuerControllersAreOffByDefault(t *testing.T) {
	// The --enable-workload-identity-issuers flag takes its default from here.
	if config.NewControllerConfig().EnableWorkloadIdentityIssuers {
		t.Fatal("the WorkloadIdentityIssuer controllers are enabled by default; they must be opted into")
	}
}

// servedKinds returns a REST mapper that maps the given kinds only.
func servedKinds(kinds ...schema.GroupVersionKind) meta.RESTMapper {
	mapper := meta.NewDefaultRESTMapper(nil)
	for _, kind := range kinds {
		mapper.Add(kind, meta.RESTScopeRoot)
	}
	return mapper
}

// failingMapper fails every lookup with an error other than a missing kind.
type failingMapper struct{ meta.RESTMapper }

func (failingMapper) RESTMapping(schema.GroupKind, ...string) (*meta.RESTMapping, error) {
	return nil, errors.New("discovery is unavailable")
}

func TestWorkloadIdentityIssuerControllersAreSetUpOnlyWhenEnabledAndServed(t *testing.T) {
	issuerKind := iamv1alpha1.SchemeGroupVersion.WithKind("WorkloadIdentityIssuer")

	// Disabled: nothing is set up, so neither the manager nor the kinds are used, even nil ones.
	registered, err := setupWorkloadIdentityIssuerControllers(false, nil, nil)
	if err != nil || registered {
		t.Fatalf("disabled: registered %v, err %v; want nothing set up", registered, err)
	}

	// Enabled, but the kind is not served: left out without an error, so the other controllers keep running.
	registered, err = setupWorkloadIdentityIssuerControllers(true, nil, servedKinds())
	if err != nil || registered {
		t.Fatalf("not served: registered %v, err %v; want nothing set up and no error", registered, err)
	}

	// Enabled, and the lookup itself fails: an error, like any other failure to set a controller up.
	registered, err = setupWorkloadIdentityIssuerControllers(true, nil, failingMapper{})
	if err == nil || !strings.Contains(err.Error(), "discovery is unavailable") || registered {
		t.Fatalf("lookup failed: registered %v, err %v; want the lookup's error", registered, err)
	}

	// Enabled and served: the controllers are built against the manager given. With no manager the builder
	// refuses them, which shows the cases above never reached the builder.
	registered, err = setupWorkloadIdentityIssuerControllers(true, nil, servedKinds(issuerKind))
	if err == nil || !strings.Contains(err.Error(), "must provide a non-nil Manager") || registered {
		t.Fatalf("served: registered %v, err %v; want the builder to refuse a nil manager", registered, err)
	}
}

func TestTheControllerSchemeRecognizesWorkloadIdentityIssuers(t *testing.T) {
	// The controllers read and write the kind through the binary's scheme, which takes it from Milo's
	// iam.miloapis.com/v1alpha1 package. A Milo version that declares the type without registering it would
	// compile and then fail at the first reconcile.
	for _, kind := range []string{"WorkloadIdentityIssuer", "WorkloadIdentityIssuerList"} {
		gvk := iamv1alpha1.SchemeGroupVersion.WithKind(kind)
		if !scheme.Recognizes(gvk) {
			t.Errorf("the controller's scheme does not recognize %s", gvk)
		}
	}
}
