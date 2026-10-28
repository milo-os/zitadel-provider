package keyset

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	mcbuilder "sigs.k8s.io/multicluster-runtime/pkg/builder"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	mcreconcile "sigs.k8s.io/multicluster-runtime/pkg/reconcile"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

// defaultOIDCMaxTokenLifetime bounds an OIDC issuer's tokens when spec.maxTokenLifetime is unset.
const defaultOIDCMaxTokenLifetime = time.Hour

// recheckInterval re-evaluates every issuer, so a Domain verified or deleted later is noticed.
const recheckInterval = 5 * time.Minute

// domainList is the networking.datumapis.com Domain kind, read without importing its module.
var domainList = schema.GroupVersionKind{Group: "networking.datumapis.com", Version: "v1alpha", Kind: "DomainList"}

// Controller verifies each WorkloadIdentityIssuer's signing keys and publishes the usable ones, with the
// issuer's exact iss value and its conditions, in status. It runs in every project control plane.
type Controller struct {
	mgr mcmanager.Manager
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=workloadidentityissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=workloadidentityissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.datumapis.com,resources=domains,verbs=get;list;watch

// Reconcile publishes one issuer's verified key set and conditions.
func (c *Controller) Reconcile(ctx context.Context, req mcreconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithName("workloadidentityissuer-keyset")
	cluster, err := c.mgr.GetCluster(ctx, req.ClusterName)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get cluster %s from manager: %w", req.ClusterName, err)
	}
	cl := cluster.GetClient()

	issuer := &iamv1alpha1.WorkloadIdentityIssuer{}
	if err := cl.Get(ctx, req.NamespacedName, issuer); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	verifiedHosts, err := verifiedDomainHosts(ctx, cl)
	if err != nil {
		// A transient failure must not flip DomainVerified: leave status as it is and try again.
		return ctrl.Result{}, fmt.Errorf("failed to list Domains: %w", err)
	}
	before := issuer.Status.DeepCopy()
	Evaluate(issuer, metav1.Now())
	SetDomainVerified(issuer, verifiedHosts)
	if !equality.Semantic.DeepEqual(before, &issuer.Status) {
		if err := cl.Status().Update(ctx, issuer); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update the issuer's status: %w", err)
		}
		log.Info("issuer status updated", "cluster", req.ClusterName, "issuer", issuer.Name,
			"ready", meta.IsStatusConditionTrue(issuer.Status.Conditions, iamv1alpha1.WorkloadIdentityIssuerReadyCondition),
			"keySetGeneration", issuer.Status.KeySetGeneration)
	}
	return ctrl.Result{RequeueAfter: recheckInterval}, nil
}

// verifiedDomainHosts returns the domain names of the project's Domains whose ownership is verified.
func verifiedDomainHosts(ctx context.Context, cl client.Client) (map[string]bool, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(domainList)
	if err := cl.List(ctx, list); err != nil {
		if meta.IsNoMatchError(err) || errors.IsNotFound(err) {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	hosts := map[string]bool{}
	for _, item := range list.Items {
		name, _, _ := unstructured.NestedString(item.Object, "spec", "domainName")
		conditions, _, _ := unstructured.NestedSlice(item.Object, "status", "conditions")
		for _, raw := range conditions {
			condition, _ := raw.(map[string]any)
			if condition["type"] == "Verified" && condition["status"] == string(metav1.ConditionTrue) && name != "" {
				hosts[strings.ToLower(name)] = true
			}
		}
	}
	return hosts, nil
}

// SetDomainVerified sets the issuer's DomainVerified condition: true when the project's verified domain
// hosts include the issuer's host exactly.
func SetDomainVerified(issuer *iamv1alpha1.WorkloadIdentityIssuer, verifiedHosts map[string]bool) {
	host := ""
	if issuer.Spec.OIDC != nil {
		if parsed, err := url.Parse(issuer.Spec.OIDC.IssuerURI); err == nil {
			host = strings.ToLower(parsed.Hostname())
		}
	}
	if host != "" && verifiedHosts[host] {
		setCondition(issuer, iamv1alpha1.WorkloadIdentityIssuerDomainVerifiedCondition, true, iamv1alpha1.WorkloadIdentityIssuerDomainVerifiedReason,
			fmt.Sprintf("Domain %s is verified in this project", host))
		return
	}
	setCondition(issuer, iamv1alpha1.WorkloadIdentityIssuerDomainVerifiedCondition, false, iamv1alpha1.WorkloadIdentityIssuerNoVerifiedDomainReason,
		fmt.Sprintf("no verified Domain in this project is %s", host))
}

// Evaluate sets the issuer's status from its spec and the time. It changes the key set's generation and
// fetch time only when the published key set changes. Status carries spec.requiredClaims too, so a
// consumer reads the whole issuer from status.
func Evaluate(issuer *iamv1alpha1.WorkloadIdentityIssuer, now metav1.Time) {
	status := &issuer.Status
	status.ObservedGeneration = issuer.Generation
	status.RequiredClaims = nil
	if len(issuer.Spec.RequiredClaims) > 0 {
		status.RequiredClaims = maps.Clone(issuer.Spec.RequiredClaims)
	}
	if issuer.Spec.Disabled {
		setCondition(issuer, iamv1alpha1.WorkloadIdentityIssuerDisabledCondition, true, iamv1alpha1.WorkloadIdentityIssuerDisabledReason, "spec.disabled is set")
	} else {
		setCondition(issuer, iamv1alpha1.WorkloadIdentityIssuerDisabledCondition, false, iamv1alpha1.WorkloadIdentityIssuerEnabledReason, "the issuer is enabled")
	}

	ready, reason, message := false, "", ""
	switch {
	case issuer.Spec.OIDC != nil:
		oidc := issuer.Spec.OIDC
		status.Issuer = oidc.IssuerURI
		lifetime := defaultOIDCMaxTokenLifetime
		if issuer.Spec.MaxTokenLifetime != nil {
			lifetime = issuer.Spec.MaxTokenLifetime.Duration
		}
		status.MaxTokenLifetime = &metav1.Duration{Duration: lifetime}

		if oidc.JWKS.Source != iamv1alpha1.JWKSSourceInline {
			ready, reason, message = false, iamv1alpha1.WorkloadIdentityIssuerKeySourceNotSupportedReason, "fetching key sets is not supported yet; use an inline key set"
			break
		}
		published, dropped, err := UsableKeys(oidc.JWKS.Inline)
		if err != nil {
			ready, reason, message = false, iamv1alpha1.WorkloadIdentityIssuerNoUsableKeysReason, err.Error()
			break
		}
		if published != status.KeySet {
			status.KeySet = published
			status.KeySetGeneration++
			status.LastFetchTime = &now
		}
		switch {
		case published == `{"keys":[]}`:
			ready, reason, message = false, iamv1alpha1.WorkloadIdentityIssuerNoUsableKeysReason, "no usable key: "+strings.Join(dropped, "; ")
		case len(dropped) > 0:
			ready, reason, message = true, iamv1alpha1.WorkloadIdentityIssuerKeysDroppedReason, "left out: "+strings.Join(dropped, "; ")
		default:
			ready, reason, message = true, iamv1alpha1.WorkloadIdentityIssuerKeySetVerifiedReason, "the key set is verified"
		}
	default:
		ready, reason, message = false, iamv1alpha1.WorkloadIdentityIssuerNoUsableKeysReason, "spec.oidc is not set"
	}
	if issuer.Spec.Disabled {
		ready, reason, message = false, iamv1alpha1.WorkloadIdentityIssuerDisabledReason, "spec.disabled is set"
	}
	setCondition(issuer, iamv1alpha1.WorkloadIdentityIssuerReadyCondition, ready, reason, message)
}

// setCondition sets one of the issuer's conditions for its current generation.
func setCondition(issuer *iamv1alpha1.WorkloadIdentityIssuer, conditionType string, ok bool, reason, message string) {
	value := metav1.ConditionFalse
	if ok {
		value = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&issuer.Status.Conditions, metav1.Condition{Type: conditionType, Status: value,
		Reason: reason, Message: message, ObservedGeneration: issuer.Generation})
}

// SetupWithManager registers the controller on the multicluster manager.
func (c *Controller) SetupWithManager(mgr mcmanager.Manager) error {
	c.mgr = mgr
	return mcbuilder.ControllerManagedBy(mgr).
		For(&iamv1alpha1.WorkloadIdentityIssuer{}).
		Named("workloadidentityissuer-keyset").
		Complete(c)
}
