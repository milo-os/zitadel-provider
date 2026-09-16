package webhook

import (
	"context"
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

// passkeyCodeMinter is the single Zitadel call this handler makes. It is declared
// here, narrow, rather than taking zitadel.API: the type is then an honest statement
// of what this endpoint can reach, and a test fake is four lines.
//
// *zitadel.SDKClient satisfies it.
type passkeyCodeMinter interface {
	CreatePasskeyRegistrationLink(ctx context.Context, userID string) (codeID, code string, err error)
}

// AccountRecoveryConfig is the operator-supplied half of the contract. Everything
// here is fixed at startup precisely so a request cannot influence it — in
// particular the template name, which a request can never supply.
type AccountRecoveryConfig struct {
	// TemplateName is the self-serve template. There is no support template here:
	// the support trigger is the apiserver's PasskeyRegistrationLink create, which
	// carries a SubjectAccessReview, a mandatory reason and a named requester. This
	// endpoint has none of those, so it may not produce a support-branded mail.
	TemplateName          string
	NotificationNamespace string
	// AllowedOrigins is the returnTo allowlist. An empty list rejects everything,
	// which is the safe direction: a missing config must not become "allow any host".
	AllowedOrigins []string
	ExpiryMinutes  int
	// UserLookupAttempts and UserLookupBaseWait bound the retry in userWithRetry,
	// which absorbs the race against create-user-account.
	UserLookupAttempts int
	UserLookupBaseWait time.Duration
	// Cooldown and MaxPerHour are the per-user mail budget. Zero disables that half
	// of the check; see recoverymail.TooSoon for why the budget exists at all.
	Cooldown   time.Duration
	MaxPerHour int
}

type AccountRecoveryHandler struct {
	Endpoint string

	client client.Client
	minter passkeyCodeMinter
	cfg    AccountRecoveryConfig
}

func NewAccountRecoveryHandler(
	c client.Client,
	minter passkeyCodeMinter,
	cfg AccountRecoveryConfig,
) *AccountRecoveryHandler {
	return &AccountRecoveryHandler{
		Endpoint: AccountRecoveryEndpoint,
		client:   c,
		minter:   minter,
		cfg:      cfg,
	}
}

type accountRecoveryRequest struct {
	UserID   string `json:"userId"`
	ReturnTo string `json:"returnTo"`
	// RequestedBy is a closed vocabulary of exactly one value, "self". It is still a
	// field rather than an assumption so a caller built against the old two-value
	// contract fails loudly instead of silently sending self-serve copy.
	RequestedBy string `json:"requestedBy"`

	// CodeID and Code are decoded only so a caller that supplies them can be
	// rejected. They must NOT be deleted: encoding/json ignores unknown fields by
	// default, so removing them would turn a forged code into a silent no-op rather
	// than a 400, and the old caller would look like it still worked.
	CodeID string `json:"codeId"`
	Code   string `json:"code"`
}

// accountRecoveryResponse is what the caller gets on success. The codeId is enough to
// seal a ticket and correlate the ceremony; the code itself goes only into the mail.
type accountRecoveryResponse struct {
	CodeID string `json:"codeId"`
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
	if req.CodeID != "" || req.Code != "" {
		// The endpoint mints its own code. A relayed one could not be checked against
		// this userId, and any random string would have been a fresh codeId — which is
		// what made the object-name dedupe and Zitadel's own minting throttle useless.
		log.Info("Rejected recovery request carrying a caller-supplied code", "userId", req.UserID)
		http.Error(w, "codeId and code are not accepted; this endpoint mints the code", http.StatusBadRequest)
		return
	}
	if req.UserID == "" || req.ReturnTo == "" {
		http.Error(w, "userId and returnTo are required", http.StatusBadRequest)
		return
	}

	if req.RequestedBy != recoverymail.RequestedBySelf {
		// "support" is deliberately not accepted: see AccountRecoveryConfig.TemplateName.
		http.Error(w, `requestedBy must be "self"`, http.StatusBadRequest)
		return
	}

	// Parsed once here and reused for the action URL, so the value the allowlist
	// approved is the value we build the link from.
	returnTo, err := url.Parse(req.ReturnTo)
	if err != nil || !returnToUsable(returnTo) || !originAllowed(returnTo, h.cfg.AllowedOrigins) {
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

	if !emailverified.IsVerified(user) {
		// Nothing is mailed to an unproven address (spec §4.1). auth-ui already inferred
		// this from listAuthMethods; this is the check that does not trust the inference.
		// It runs before the mint, so an unverified target costs Zitadel nothing either.
		log.Info("Refusing recovery mail for unverified address", "userId", req.UserID)
		http.Error(w, "email address is not verified", http.StatusUnprocessableEntity)
		return
	}

	tooSoon, err := recoverymail.TooSoon(r.Context(), h.client, h.cfg.NotificationNamespace,
		req.UserID, recoverymail.RequestedBySelf, h.cfg.Cooldown, h.cfg.MaxPerHour)
	if err != nil {
		// Fail closed: an unreadable list is not evidence that nothing was sent, and
		// waving the request through would hand an attacker the bypass.
		log.Error(err, "Failed to evaluate the recovery mail budget", "userId", req.UserID)
		http.Error(w, "failed to check recent activity", http.StatusInternalServerError)
		return
	}
	if tooSoon {
		// No detail. This endpoint is reachable with any userId, so naming the account
		// or when it was last mailed would confirm it exists and leak its activity.
		log.Info("Refusing recovery mail; the user is inside the cooldown", "userId", req.UserID)
		http.Error(w, "try again later", http.StatusTooManyRequests)
		return
	}

	codeID, code, err := h.minter.CreatePasskeyRegistrationLink(r.Context(), req.UserID)
	if err != nil {
		// err carries no code: CreatePasskeyRegistrationLink fails before there is one.
		log.Error(err, "Failed to mint a passkey registration code", "userId", req.UserID)
		http.Error(w, "failed to create recovery code", http.StatusInternalServerError)
		return
	}

	email := recoverymail.Build(recoverymail.Input{
		User:          user,
		UserID:        req.UserID,
		CodeID:        codeID,
		Code:          code,
		ActionURL:     recoverymail.ActionURL(returnTo, req.UserID, codeID, code),
		TemplateName:  h.cfg.TemplateName,
		Namespace:     h.cfg.NotificationNamespace,
		ExpiryMinutes: h.cfg.ExpiryMinutes,
		RequestedBy:   recoverymail.RequestedBySelf,
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

	log.Info("Created recovery Email", "userId", req.UserID, "emailName", email.Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(accountRecoveryResponse{CodeID: codeID}); err != nil {
		log.Error(err, "Failed to write recovery response", "userId", req.UserID)
	}
}
