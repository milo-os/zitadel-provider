package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	authenticationv1 "k8s.io/api/authentication/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type Request struct {
	authenticationv1.TokenReview
}

type Response struct {
	authenticationv1.TokenReview
}

type HandlerFunc func(context.Context, Request) Response

type Handler interface {
	Handle(context.Context, Request) Response
}

// Handle calls f(ctx, req) allowing HandlerFunc to satisfy the Handler interface.
func (f HandlerFunc) Handle(ctx context.Context, req Request) Response {
	return f(ctx, req)
}

func (wh *Webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Create a logger scoped to this request.
	log := logf.FromContext(r.Context()).WithName("authentication-webhook-http")
	log.Info("Handling request", "method", r.Method, "remoteAddr", r.RemoteAddr)

	// Only POST is allowed as per the TokenReview API semantics.
	if r.Method != http.MethodPost {
		log.Error(nil, "Method not allowed", "method", r.Method)
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode the incoming TokenReview request.
	var review authenticationv1.TokenReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		log.Error(err, "Failed to decode TokenReview")
		errResponse := Errored(err)
		wh.writeResponse(w, errResponse)
		return
	}

	reviewResponse := wh.Handler.Handle(r.Context(), Request{TokenReview: review})

	// On a denial the username and uid are empty by construction, so without
	// the evaluation error this line records only that *something* was refused.
	// The reason is already on the response; it just was not being logged.
	kv := []any{
		"authenticated", reviewResponse.Status.Authenticated,
		"username", reviewResponse.Status.User.Username,
		"uid", reviewResponse.Status.User.UID,
	}
	if !reviewResponse.Status.Authenticated && reviewResponse.Status.Error != "" {
		kv = append(kv, "reason", reviewResponse.Status.Error)
	}

	log.Info("Request processed", kv...)

	wh.writeResponse(w, reviewResponse)
}

func (wh *Webhook) writeResponse(w http.ResponseWriter, resp Response) {
	log := logf.Log.WithName("authentication-webhook-http")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp.TokenReview); err != nil {
		log.Error(err, "Failed to encode response")
		http.Error(w, fmt.Sprintf("failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
	log.V(1).Info("Response written", "authenticated", resp.Status.Authenticated)
}
