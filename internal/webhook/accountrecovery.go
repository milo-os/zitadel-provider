package webhook

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"go.miloapis.com/auth-provider-zitadel/internal/emailverified"
	"go.miloapis.com/auth-provider-zitadel/internal/recoverymail"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// AccountRecoveryEndpoint is the path auth-ui posts to.
const AccountRecoveryEndpoint = "/v1/email/recovery"

// AccountRecoveryConfig is the operator-supplied half of the contract. Everything
// here is fixed at startup precisely so a request cannot influence it — in
// particular the two template names, which a request selects between but can
// never supply.
type AccountRecoveryConfig struct {
	// TemplateName is the self-serve template; SupportTemplateName is the one whose
	// copy says Datum Support sent the link.
	TemplateName          string
	SupportTemplateName   string
	NotificationNamespace string
	// AllowedOrigins is the returnTo allowlist. An empty list rejects everything,
	// which is the safe direction: a missing config must not become "allow any host".
	AllowedOrigins []string
	ExpiryMinutes  int
	// UserLookupAttempts and UserLookupBaseWait bound the retry in userWithRetry,
	// which absorbs the race against create-user-account.
	UserLookupAttempts int
	UserLookupBaseWait time.Duration
}

type AccountRecoveryHandler struct {
	Endpoint string

	client client.Client
	cfg    AccountRecoveryConfig
}

func NewAccountRecoveryHandler(c client.Client, cfg AccountRecoveryConfig) *AccountRecoveryHandler {
	return &AccountRecoveryHandler{Endpoint: AccountRecoveryEndpoint, client: c, cfg: cfg}
}

type accountRecoveryRequest struct {
	UserID   string `json:"userId"`
	CodeID   string `json:"codeId"`
	Code     string `json:"code"`
	ReturnTo string `json:"returnTo"`
	// RequestedBy is a closed vocabulary — "self" or "support". It selects between
	// the two configured templates; anything else is rejected rather than defaulted,
	// so a typo cannot quietly send the wrong copy.
	RequestedBy string `json:"requestedBy"`
}

func (h *AccountRecoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context()).WithName("accountRecoveryHandler")

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req accountRecoveryRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.UserID == "" || req.CodeID == "" || req.Code == "" || req.ReturnTo == "" {
		http.Error(w, "userId, codeId, code and returnTo are required", http.StatusBadRequest)
		return
	}

	template, ok := h.templateFor(req.RequestedBy)
	if !ok {
		http.Error(w, "requestedBy must be one of: self, support", http.StatusBadRequest)
		return
	}

	// Parsed once here and reused for the action URL, so the value the allowlist
	// approved is the value we build the link from.
	returnTo, err := url.Parse(req.ReturnTo)
	if err != nil || returnTo.Scheme == "" || returnTo.Host == "" || !originAllowed(returnTo, h.cfg.AllowedOrigins) {
		// Deliberately does not echo the value: this is the phishing guard, and the
		// rejected origin is attacker-controlled input.
		log.Info("Rejected returnTo outside the allowlist", "userId", req.UserID)
		http.Error(w, "returnTo is not allowed", http.StatusBadRequest)
		return
	}

	user, err := userWithRetry(r.Context(), h.client, req.UserID, h.cfg.UserLookupAttempts, h.cfg.UserLookupBaseWait)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("No User for recovery mail", "userId", req.UserID)
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		log.Error(err, "Failed to read User", "userId", req.UserID)
		http.Error(w, "failed to read user", http.StatusInternalServerError)
		return
	}

	if !emailverified.IsTrue(user) {
		// Nothing is mailed to an unproven address (spec §4.1). auth-ui already inferred
		// this from listAuthMethods; this is the check that does not trust the inference,
		// and it is the only one the support trigger has.
		log.Info("Refusing recovery mail for unverified address", "userId", req.UserID)
		http.Error(w, "email address is not verified", http.StatusUnprocessableEntity)
		return
	}

	email := recoverymail.Build(recoverymail.Input{
		User:          user,
		UserID:        req.UserID,
		CodeID:        req.CodeID,
		Code:          req.Code,
		ActionURL:     recoverymail.ActionURL(returnTo, req.UserID, req.CodeID, req.Code),
		TemplateName:  template,
		Namespace:     h.cfg.NotificationNamespace,
		ExpiryMinutes: h.cfg.ExpiryMinutes,
		RequestedBy:   req.RequestedBy,
	})

	if err := h.client.Create(r.Context(), email); err != nil && !apierrors.IsAlreadyExists(err) {
		// Not the raw error: the code sits in this Email's Variables, and an apiserver
		// rejection can echo a submitted value straight back. Reason is fixed vocabulary.
		reason := apierrors.ReasonForError(err)
		log.Error(fmt.Errorf("apiserver rejected Email create: %s", reason),
			"Failed to create recovery Email", "userId", req.UserID)
		http.Error(w, "failed to create email", http.StatusInternalServerError)
		return
	}

	// AlreadyExists means an earlier POST with this same userID+codeID already queued
	// the mail. Report success: the caller wanted a mail sent, and one was.
	log.Info("Created recovery Email", "userId", req.UserID, "emailName", email.Name,
		"requestedBy", req.RequestedBy)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// templateFor maps the closed requestedBy vocabulary onto the configured templates.
// The handler cannot be told which template to use by a request; it can only be told
// which of the two the operator configured.
func (h *AccountRecoveryHandler) templateFor(requestedBy string) (string, bool) {
	switch requestedBy {
	case recoverymail.RequestedBySelf:
		return h.cfg.TemplateName, true
	case recoverymail.RequestedBySupport:
		return h.cfg.SupportTemplateName, true
	default:
		return "", false
	}
}
