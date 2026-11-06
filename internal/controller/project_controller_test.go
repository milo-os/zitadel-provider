package controller

import (
	"context"
	"testing"

	resourcemanager "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type finalizerFunc func(context.Context, client.Object) (finalizer.Result, error)

func (f finalizerFunc) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	return f(ctx, obj)
}

func TestProjectFinalizerUpdateRace(t *testing.T) {
	for name, tc := range map[string]struct {
		updateErr error
		requeue   bool
	}{
		"another writer changed the project": {
			updateErr: apierrors.NewConflict(schema.GroupResource{Resource: "projects"}, "p", nil),
			requeue:   true,
		},
		"the project is already gone": {
			updateErr: apierrors.NewNotFound(schema.GroupResource{Resource: "projects"}, "p"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := resourcemanager.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			project := &resourcemanager.Project{ObjectMeta: metav1.ObjectMeta{Name: "p"}}
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(project).
				WithInterceptorFuncs(interceptor.Funcs{
					Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
						return tc.updateErr
					},
				}).Build()

			finalizers := finalizer.NewFinalizers()
			noop := finalizerFunc(func(context.Context, client.Object) (finalizer.Result, error) { return finalizer.Result{}, nil })
			if err := finalizers.Register(projectFinalizerKey, noop); err != nil {
				t.Fatal(err)
			}
			r := &ProjectController{Client: cl, Finalizers: finalizers}

			result, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(project)})
			if err != nil {
				t.Fatalf("a finalizer update race is not a reconcile error: %v", err)
			}
			if got := result.RequeueAfter > 0; got != tc.requeue {
				t.Fatalf("requeue = %v, want %v (%+v)", got, tc.requeue, result)
			}
		})
	}
}
