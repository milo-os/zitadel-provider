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
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pkgzitadel "go.miloapis.com/auth-provider-zitadel/pkg/zitadel"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ServiceAccount Controller", func() {
	Context("when updating ready status", func() {
		It("publishes the authoritative authentication provider client ID", func() {
			serviceAccount := &iammiloapiscomv1alpha1.ServiceAccount{
				Spec: iammiloapiscomv1alpha1.ServiceAccountSpec{State: activeServiceAccountState},
			}
			user := &pkgzitadel.User{ID: "349624629"}

			Expect(setServiceAccountReadyStatus(serviceAccount, user, "connector@platform.identity.miloapis.com")).To(Succeed())

			Expect(serviceAccount.Status.ClientID).To(Equal(user.ID))
			Expect(serviceAccount.Status.Email).To(Equal("connector@platform.identity.miloapis.com"))
			Expect(serviceAccount.Status.State).To(Equal(activeServiceAccountState))
			Expect(serviceAccount.Status.Conditions).To(HaveLen(1))
			Expect(serviceAccount.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(serviceAccount.Status.Conditions[0].Status).To(Equal(metav1.ConditionTrue))
		})

		It("backfills client ID for an existing ready service account", func() {
			serviceAccount := &iammiloapiscomv1alpha1.ServiceAccount{
				Spec: iammiloapiscomv1alpha1.ServiceAccountSpec{State: activeServiceAccountState},
				Status: iammiloapiscomv1alpha1.ServiceAccountStatus{
					Email: "existing@platform.identity.miloapis.com",
					State: activeServiceAccountState,
					Conditions: []metav1.Condition{{
						Type:    "Ready",
						Status:  metav1.ConditionTrue,
						Reason:  "Reconciled",
						Message: "ServiceAccount successfully reconciled",
					}},
				},
			}

			Expect(setServiceAccountReadyStatus(serviceAccount, &pkgzitadel.User{ID: "existing-client-id"}, serviceAccount.Status.Email)).To(Succeed())

			Expect(serviceAccount.Status.ClientID).To(Equal("existing-client-id"))
			Expect(serviceAccount.Status.Conditions).To(HaveLen(1))
			Expect(serviceAccount.Status.Conditions[0].Status).To(Equal(metav1.ConditionTrue))
		})

		It("does not mark the account ready without a client ID", func() {
			serviceAccount := &iammiloapiscomv1alpha1.ServiceAccount{}

			Expect(setServiceAccountReadyStatus(serviceAccount, &pkgzitadel.User{}, "missing@platform.identity.miloapis.com")).To(MatchError("authentication provider returned an empty service account client ID"))
			Expect(serviceAccount.Status.Conditions).To(BeEmpty())
		})
	})
})
