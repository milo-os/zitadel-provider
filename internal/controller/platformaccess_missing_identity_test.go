package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.miloapis.com/auth-provider-zitadel/internal/zitadel"
	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestPlatformAccessMissingIdentity(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			response := code
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v2/users/missing-user" {
					t.Errorf("unexpected identity mutation: %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(response)
				if response == http.StatusOK {
					_, _ = w.Write([]byte(`{"user":{"state":"USER_STATE_ACTIVE"}}`))
				}
			}))
			defer server.Close()
			scheme := runtime.NewScheme()
			if err := iam.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			pa := &iam.PlatformAccess{ObjectMeta: metav1.ObjectMeta{Name: "missing-user"}, Spec: iam.PlatformAccessSpec{UserRef: iam.UserReference{Name: "missing-user"}, State: iam.PlatformAccessStateApproved}}
			cl := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(pa).WithObjects(pa, &iam.User{ObjectMeta: metav1.ObjectMeta{Name: "missing-user"}}).Build()
			r := &PlatformAccessController{Client: cl, Zitadel: zitadel.NewClientWithTokenSource(server.URL, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"}))}
			req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(pa)}
			result, err := r.Reconcile(context.Background(), req)
			if code == http.StatusInternalServerError {
				if err == nil {
					t.Fatal("server failure was suppressed")
				}
				return
			}
			if err != nil || result.RequeueAfter != userStateRequeueAfter {
				t.Fatalf("result=%+v error=%v", result, err)
			}
			if err := cl.Get(context.Background(), req.NamespacedName, pa); err != nil {
				t.Fatal(err)
			}
			if len(pa.Status.Conditions) != 1 || pa.Status.Conditions[0].Reason != "ZitadelUserNotFound" || pa.Status.Conditions[0].Status != metav1.ConditionFalse {
				t.Fatalf("unexpected conditions: %+v", pa.Status.Conditions)
			}
			response = http.StatusOK
			if _, err := r.Reconcile(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			if err := cl.Get(context.Background(), req.NamespacedName, pa); err != nil {
				t.Fatal(err)
			}
			if pa.Status.Conditions[0].Status != metav1.ConditionTrue {
				t.Fatalf("identity did not recover: %+v", pa.Status.Conditions)
			}
		})
	}
}
