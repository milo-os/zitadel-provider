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
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pkgzitadel "go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	resourcemanagermiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
)

const (
	projectFinalizerKey    = "auth-provider-zitadel.miloapis.com/project"
	projectConflictRequeue = time.Second
)

// ProjectController reconciles Project resources in the main cluster.
// It watches Project resources and maintains a 1:1 mapping to Zitadel Organizations.
// On Project creation, a Zitadel Organization is created with the Project UID as the org ID and name.
// On Project deletion, the Zitadel Organization is deleted (handled by finalizer).
type ProjectController struct {
	Finalizers finalizer.Finalizers
	Zitadel    pkgzitadel.API
	Client     client.Client
}

type projectFinalizer struct {
	Zitadel pkgzitadel.API
}

// Finalize handles cleanup when a Project is deleted.
// It deletes the corresponding Zitadel Organization.
func (f *projectFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx).WithName("project-finalizer")
	log.Info("Starting finalization for Project")

	project, ok := obj.(*resourcemanagermiloapiscomv1alpha1.Project)
	if !ok {
		err := fmt.Errorf("unexpected object type %T, expected Project", obj)
		log.Error(err, "Type assertion failed")
		return finalizer.Result{}, err
	}

	orgID := pkgzitadel.OrgIDForProject(project.GetName())
	log.Info("Deleting Zitadel Organization", "orgID", orgID)

	err := f.Zitadel.DeleteOrganization(ctx, orgID)
	if err != nil {
		log.Error(err, "Failed to delete Zitadel Organization", "orgID", orgID)
		return finalizer.Result{}, fmt.Errorf("delete organization: %w", err)
	}

	log.Info("Successfully finalized Project", "orgID", orgID)
	return finalizer.Result{}, nil
}

// +kubebuilder:rbac:groups=resourcemanager.miloapis.com,resources=projects,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=resourcemanager.miloapis.com,resources=projects/status,verbs=get;update
// +kubebuilder:rbac:groups=resourcemanager.miloapis.com,resources=projects/finalizers,verbs=update

// Reconcile ENSURES the finalizer is present for deletion logic, but cleans up any status conditions previously set.
func (r *ProjectController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithName("project-reconciler")

	project := &resourcemanagermiloapiscomv1alpha1.Project{}
	if err := r.Client.Get(ctx, req.NamespacedName, project); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Project")
		return ctrl.Result{}, fmt.Errorf("get project: %w", err)
	}

	// Manage finalizers. This will add the finalizer if not present and execute it if deleting.
	finalizeResult, err := r.Finalizers.Finalize(ctx, project)
	if err != nil {
		log.Error(err, "Failed to run finalizers")
		return ctrl.Result{}, fmt.Errorf("finalize: %w", err)
	}
	if finalizeResult.Updated {
		log.Info("Finalizer updated the object. Updating API server")
		if err := r.Client.Update(ctx, project); err != nil {
			if errors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}
			if errors.IsConflict(err) {
				log.V(1).Info("Project changed while updating its finalizer; requeuing")
				return ctrl.Result{RequeueAfter: projectConflictRequeue}, nil
			}
			log.Error(err, "Failed to update Project after finalizer")
			return ctrl.Result{}, fmt.Errorf("update project after finalizer: %w", err)
		}
	}

	// If object is marked for deletion, we are done (finalizer should have run).
	if project.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the given manager.
func (r *ProjectController) SetupWithManager(mgr ctrl.Manager) error {
	log := logf.Log.WithName("project-controller-setup")
	log.Info("Setting up Project controller")

	r.Finalizers = finalizer.NewFinalizers()
	projectFin := &projectFinalizer{
		Zitadel: r.Zitadel,
	}
	if err := r.Finalizers.Register(projectFinalizerKey, projectFin); err != nil {
		return fmt.Errorf("register project finalizer: %w", err)
	}
	r.Client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		For(&resourcemanagermiloapiscomv1alpha1.Project{}).
		Complete(r)
}
