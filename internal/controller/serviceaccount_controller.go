/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"strings"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	mcbuilder "sigs.k8s.io/multicluster-runtime/pkg/builder"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	mcreconcile "sigs.k8s.io/multicluster-runtime/pkg/reconcile"

	pkgzitadel "go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
)

const (
	serviceAccountFinalizerKey  = "iam.miloapis.com/serviceaccount"
	inactiveServiceAccountState = "Inactive"
	activeServiceAccountState   = "Active"
)

// ServiceAccountController reconciles a ServiceAccount object
type ServiceAccountController struct {
	Finalizers         finalizer.Finalizers
	Zitadel            pkgzitadel.API
	EmailAddressSuffix string
	mgr                mcmanager.Manager
}

type serviceAccountFinalizer struct {
	Zitadel pkgzitadel.API
}

func (f *serviceAccountFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx).WithName("serviceaccount-finalizer")
	log.Info("Starting finalization")

	serviceAccount, ok := obj.(*iammiloapiscomv1alpha1.ServiceAccount)
	if !ok {
		err := fmt.Errorf("unexpected object type %T, expected ServiceAccount", obj)
		log.Error(err, "Type assertion failed")
		return finalizer.Result{}, fmt.Errorf("type assertion failed: %w", err)
	}

	userID := string(serviceAccount.GetUID())
	log.Info("Checking if service account exists in Zitadel", "userID", userID)

	user, err := f.Zitadel.GetUserByID(ctx, userID)
	if err != nil {
		log.Error(err, "Failed to get user from Zitadel", "userID", userID)
		return finalizer.Result{}, fmt.Errorf("get user by id: %w", err)
	}

	if user == nil {
		log.Info("Service account not found in Zitadel, nothing to clean up", "userID", userID)
		return finalizer.Result{}, nil
	}

	log.Info("Deleting service account from Zitadel", "userID", userID)
	err = f.Zitadel.DeleteUser(ctx, userID)
	if err != nil {
		log.Error(err, "Failed to delete user from Zitadel", "userID", userID)
		return finalizer.Result{}, fmt.Errorf("delete user: %w", err)
	}

	log.Info("Successfully finalized service account", "userID", userID)
	return finalizer.Result{}, nil
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=serviceaccounts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=serviceaccounts/finalizers,verbs=update

func (r *ServiceAccountController) Reconcile(ctx context.Context, req mcreconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithName("serviceaccount-reconciler")
	log.Info("Starting reconciliation", "request", req)

	cluster, err := r.mgr.GetCluster(ctx, req.ClusterName)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get cluster %s from manager: %w", req.ClusterName, err)
	}

	serviceAccount := &iammiloapiscomv1alpha1.ServiceAccount{}
	err = cluster.GetClient().Get(ctx, req.NamespacedName, serviceAccount)
	if errors.IsNotFound(err) {
		log.Info("ServiceAccount resource not found")
		return ctrl.Result{}, nil
	} else if err != nil {
		log.Error(err, "Failed to get ServiceAccount resource")
		return ctrl.Result{}, fmt.Errorf("failed to get ServiceAccount resource: %w", err)
	}

	log.Info("Running finalizers", "serviceAccountName", serviceAccount.GetName(), "serviceAccountUID", serviceAccount.GetUID())
	finalizeResult, err := r.Finalizers.Finalize(ctx, serviceAccount)
	if err != nil {
		log.Error(err, "Failed to run finalizers for ServiceAccount")
		return ctrl.Result{}, fmt.Errorf("failed to run finalizers for ServiceAccount: %w", err)
	}
	if finalizeResult.Updated {
		log.Info("Finalizer updated the serviceAccount object, updating API server")
		if updateErr := cluster.GetClient().Update(ctx, serviceAccount); updateErr != nil {
			log.Error(updateErr, "Failed to update ServiceAccount after finalizer update")
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	projectName := strings.TrimPrefix(string(req.ClusterName), "/")
	orgID := pkgzitadel.OrgIDForProject(projectName)
	log.V(2).Info("Checking if Zitadel organization exists", "orgID", orgID)
	org, err := r.Zitadel.GetOrganization(ctx, orgID)
	if err != nil {
		log.Error(err, "Failed to check if Zitadel Organization exists", "orgID", orgID)
		return ctrl.Result{}, fmt.Errorf("get organization: %w", err)
	}

	if org == nil {
		displayName := pkgzitadel.OrgDisplayNameForProject(projectName)
		log.Info("Zitadel Organization does not exist, creating it", "orgID", orgID, "displayName", displayName)
		if _, err := r.Zitadel.CreateOrganizationWithID(ctx, displayName, orgID); err != nil {
			log.Error(err, "Failed to create Zitadel Organization", "orgID", orgID)
			return ctrl.Result{}, fmt.Errorf("create organization: %w", err)
		}
		log.Info("Successfully created Zitadel Organization", "orgID", orgID, "displayName", displayName)
	}

	saComputedEmail := r.computeEmailAddress(serviceAccount, req)
	userID := string(serviceAccount.GetUID())
	log.Info("Checking if service account exists in Zitadel", "userID", userID, "orgID", orgID)

	user, err := r.Zitadel.GetUserByID(ctx, userID)
	if err != nil {
		log.Error(err, "Failed to get user from Zitadel", "userID", userID)
		return ctrl.Result{}, fmt.Errorf("get user by id: %w", err)
	}

	if user == nil {
		log.Info("Service account not found in Zitadel, creating it", "userID", userID, "orgID", orgID)
		createdUserID, err := r.Zitadel.AddMachineUserInOrganization(ctx, orgID, userID, saComputedEmail, serviceAccount.GetName())
		if err != nil {
			log.Error(err, "Failed to create service account user in Zitadel", "userID", userID, "orgID", orgID)
			return ctrl.Result{}, fmt.Errorf("add machine user in organization: %w", err)
		}
		user = &pkgzitadel.User{ID: createdUserID}
		log.Info("Successfully created service account in Zitadel", "userID", userID, "orgID", orgID)
	}

	if serviceAccount.Status.State != serviceAccount.Spec.State {
		if err := r.updateServiceAccountState(ctx, orgID, serviceAccount); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update service account state: %w", err)
		}
	}

	if serviceAccount.GetDeletionTimestamp() != nil {
		log.Info("ServiceAccount is marked for deletion, stopping reconciliation")
		return ctrl.Result{}, nil
	}

	log.Info("Updating ServiceAccount status", "serviceAccountName", serviceAccount.GetName())
	if err := setServiceAccountReadyStatus(serviceAccount, user, saComputedEmail); err != nil {
		return ctrl.Result{}, err
	}
	if err := cluster.GetClient().Status().Update(ctx, serviceAccount); err != nil {
		log.Error(err, "Failed to update ServiceAccount status")
		return ctrl.Result{}, fmt.Errorf("failed to update ServiceAccount status: %w", err)
	}

	log.Info("Successfully reconciled ServiceAccount")
	return ctrl.Result{}, nil
}

func setServiceAccountReadyStatus(serviceAccount *iammiloapiscomv1alpha1.ServiceAccount, user *pkgzitadel.User, email string) error {
	if user == nil || user.ID == "" {
		return fmt.Errorf("authentication provider returned an empty service account client ID")
	}

	serviceAccount.Status.ClientID = user.ID
	serviceAccount.Status.Email = email
	serviceAccount.Status.State = serviceAccount.Spec.State
	serviceAccountCondition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Reconciled",
		Message:            "ServiceAccount successfully reconciled",
		LastTransitionTime: metav1.Now(),
	}
	meta.SetStatusCondition(&serviceAccount.Status.Conditions, serviceAccountCondition)
	return nil
}

func (r *ServiceAccountController) updateServiceAccountState(ctx context.Context, orgID string, serviceAccount *iammiloapiscomv1alpha1.ServiceAccount) error {
	log := logf.FromContext(ctx).WithName("serviceaccount-reconciler")

	userID := string(serviceAccount.GetUID())
	skipUpdate := false
	var updateFnc func(ctx context.Context, orgID, userID string) error

	switch serviceAccount.Spec.State {
	case activeServiceAccountState:
		if serviceAccount.Status.State == "" {
			log.Info("New Service Account. Zitadel default state is Active")
			skipUpdate = true
		}
		log.Info("Reactivating service account", "userID", userID, "orgID", orgID)
		updateFnc = r.Zitadel.ReactivateUser

	case inactiveServiceAccountState:
		log.Info("Deactivating service account", "userID", userID, "orgID", orgID)
		updateFnc = r.Zitadel.DeactivateUser

	default:
		log.Error(fmt.Errorf("invalid state: %s", serviceAccount.Spec.State), "Invalid state")
		return fmt.Errorf("invalid state: %s", serviceAccount.Spec.State)
	}

	if !skipUpdate {
		log.Info("Updating service account state", "userID", userID, "orgID", orgID)
		err := updateFnc(ctx, orgID, userID)
		if err != nil {
			log.Error(err, "Failed to update service account on Zitadel", "userID", userID, "orgID", orgID)
			return err
		}
		log.Info("Successfully updated service account", "userID", userID, "orgID", orgID)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ServiceAccountController) SetupWithManager(mgr mcmanager.Manager) error {
	r.Finalizers = finalizer.NewFinalizers()
	r.mgr = mgr

	if err := r.Finalizers.Register(serviceAccountFinalizerKey, &serviceAccountFinalizer{
		Zitadel: r.Zitadel,
	}); err != nil {
		return fmt.Errorf("failed to register service account finalizer: %w", err)
	}

	return mcbuilder.ControllerManagedBy(mgr).
		For(&iammiloapiscomv1alpha1.ServiceAccount{}).
		Named("serviceaccount").
		Complete(r)
}

// computeEmailAddress computes the email address for a service account.
// EmailAddress is {metadata.name}@{project-name}.{EmailAddressSuffix}
func (r *ServiceAccountController) computeEmailAddress(serviceAccount *iammiloapiscomv1alpha1.ServiceAccount, req mcreconcile.Request) string {
	projectName := strings.TrimPrefix(string(req.ClusterName), "/")
	return serviceAccount.GetName() + "@" + projectName + "." + r.EmailAddressSuffix
}
