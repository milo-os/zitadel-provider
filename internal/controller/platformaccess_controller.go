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

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"go.miloapis.com/auth-provider-zitadel/internal/zitadel"
)

const (
	ZitadelReadyCondition = "ZitadelReady"
	fieldOwnerName        = "auth-provider-zitadel"
	userStateWaitReason   = "WaitingForUserState"
	userStateRequeueAfter = 30 * time.Second
)

type PlatformAccessController struct {
	Client  client.Client
	Zitadel *zitadel.Client
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=platformaccesses,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=platformaccesses/status,verbs=update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users,verbs=get

func (r *PlatformAccessController) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithName("platformaccess-reconciler")

	platformAccess := &iammiloapiscomv1alpha1.PlatformAccess{}
	if err := r.Client.Get(ctx, req.NamespacedName, platformAccess); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get PlatformAccess resource: %w", err)
	}

	userName := platformAccess.Spec.UserRef.Name
	if _, err := r.getUser(ctx, userName); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get User resource: %w", err)
	}

	var reconcileErr error
	var waitingForUserState bool
	// Only sync to Zitadel if the platform access state actually changed
	if r.stateChanged(platformAccess) {
		expectActive := r.expectActive(platformAccess.Spec.State)
		log.Info("Aligning Zitadel user state", "userName", userName, "state", platformAccess.Spec.State, "expectActive", expectActive)

		var err error
		waitingForUserState, err = r.ensureZitadelUserState(ctx, userName, expectActive)
		if err != nil {
			log.Error(err, "Failed to align Zitadel user state", "userName", userName)
			reconcileErr = err
		}
	}

	oldPlatformAccess := platformAccess.DeepCopy()
	r.updateStatusConditions(&platformAccess.Status, platformAccess.Spec.State, reconcileErr, waitingForUserState)

	if r.shouldUpdateStatus(&oldPlatformAccess.Status, &platformAccess.Status) {
		patch := client.MergeFrom(oldPlatformAccess)
		if err := r.Client.Status().Patch(ctx, platformAccess, patch, client.FieldOwner(fieldOwnerName)); err != nil {
			log.Error(err, "Failed to patch PlatformAccess status")
			return ctrl.Result{}, fmt.Errorf("failed to patch PlatformAccess status: %w", err)
		}
	}

	if reconcileErr != nil {
		return ctrl.Result{}, reconcileErr
	}

	if waitingForUserState {
		log.Info("Zitadel user is not yet in a state that allows syncing; requeuing", "userName", userName, "requeueAfter", userStateRequeueAfter)
		return ctrl.Result{RequeueAfter: userStateRequeueAfter}, nil
	}

	log.Info("Reconciliation completed", "userName", userName)
	return ctrl.Result{}, nil
}

func (r *PlatformAccessController) SetupWithManager(mgr manager.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&iammiloapiscomv1alpha1.PlatformAccess{}).
		Named("platformaccess").
		Complete(r)
}

func (r *PlatformAccessController) getUser(ctx context.Context, userName string) (*iammiloapiscomv1alpha1.User, error) {
	user := &iammiloapiscomv1alpha1.User{}
	err := r.Client.Get(ctx, client.ObjectKey{Name: userName}, user)
	return user, err
}

func (r *PlatformAccessController) expectActive(state iammiloapiscomv1alpha1.PlatformAccessState) bool {
	return state != iammiloapiscomv1alpha1.PlatformAccessStateSuspended
}

func (r *PlatformAccessController) stateChanged(platformAccess *iammiloapiscomv1alpha1.PlatformAccess) bool {
	cond := meta.FindStatusCondition(platformAccess.Status.Conditions, ZitadelReadyCondition)
	return cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != string(platformAccess.Spec.State)
}

// ensureZitadelUserState aligns the Zitadel user's active/inactive state with expectActive.
// It returns waitingForUserState=true when the user is currently in a state (e.g. still
// initial, or locked) from which Zitadel won't accept a reactivate/deactivate call, so the
// caller can requeue and retry once that state has a chance to change.
func (r *PlatformAccessController) ensureZitadelUserState(ctx context.Context, userName string, expectActive bool) (waitingForUserState bool, err error) {
	userResp, err := r.Zitadel.GetUser(ctx, userName)
	if err != nil {
		return false, fmt.Errorf("failed to get user state from Zitadel: %w", err)
	}

	currentState := userResp.User.State
	if expectActive && currentState == zitadel.UserStateActive {
		return false, nil
	}
	if !expectActive && currentState == zitadel.UserStateInactive {
		return false, nil
	}

	log := logf.FromContext(ctx)

	if expectActive {
		if currentState != zitadel.UserStateInactive {
			log.Info("User is not inactive yet; deferring reactivation", "userName", userName, "currentState", currentState)
			return true, nil
		}
		return false, r.Zitadel.ReactivateUser(ctx, userName)
	}

	if currentState != zitadel.UserStateActive {
		log.Info("User is not active yet; deferring deactivation", "userName", userName, "currentState", currentState)
		return true, nil
	}
	return false, r.Zitadel.DeactivateUser(ctx, userName)
}

func (r *PlatformAccessController) updateStatusConditions(status *iammiloapiscomv1alpha1.PlatformAccessStatus, state iammiloapiscomv1alpha1.PlatformAccessState, err error, waitingForUserState bool) {
	cond := metav1.Condition{
		Type:               ZitadelReadyCondition,
		LastTransitionTime: metav1.Now(),
	}

	switch {
	case err != nil:
		cond.Status = metav1.ConditionFalse
		cond.Reason = "SyncFailed"
		cond.Message = fmt.Sprintf("Failed to align Zitadel user state: %s", err.Error())
	case waitingForUserState:
		cond.Status = metav1.ConditionFalse
		cond.Reason = userStateWaitReason
		cond.Message = "Waiting for the Zitadel user to reach a state that allows syncing"
	default:
		cond.Status = metav1.ConditionTrue
		cond.Reason = string(state)
		cond.Message = fmt.Sprintf("Zitadel user state successfully aligned to %s", state)
	}

	meta.SetStatusCondition(&status.Conditions, cond)
}

func (r *PlatformAccessController) shouldUpdateStatus(oldStatus, newStatus *iammiloapiscomv1alpha1.PlatformAccessStatus) bool {
	return !equality.Semantic.DeepEqual(oldStatus, newStatus)
}
