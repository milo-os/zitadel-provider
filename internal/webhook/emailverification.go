package webhook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// EmailVerificationEndpoint is the path auth-ui posts to.
const EmailVerificationEndpoint = "/v1/email/verification"

// maxRequestBytes caps the request body. The payload is three short strings; anything
// larger is a mistake or an attempt to make us allocate.
const maxRequestBytes = 64 << 10

// defaultExpiryMinutes is the fallback when the operator supplies no lifetime. Config
// normally sets this; rendering "expires in 0 minutes" to a user is worse than a stale
// number, so an unset value falls back rather than passing through.
const defaultExpiryMinutes = 60

// EmailVerificationConfig is the operator-supplied half of the contract. Everything
// here is fixed at startup precisely so a request cannot influence it.
type EmailVerificationConfig struct {
	TemplateName          string
	NotificationNamespace string
	// AllowedOrigins is the returnTo allowlist. An empty list rejects everything,
	// which is the safe direction: a missing config must not become "allow any host".
	AllowedOrigins []string
	ExpiryMinutes  int
	// UserLookupAttempts and UserLookupBaseWait bound the retry in userWithRetry
	// below, which absorbs the signup race against create-user-account.
	UserLookupAttempts int
	UserLookupBaseWait time.Duration
}

type EmailVerificationHandler struct {
	Endpoint string

	client client.Client
	cfg    EmailVerificationConfig
}

func NewEmailVerificationHandler(c client.Client, cfg EmailVerificationConfig) *EmailVerificationHandler {
	return &EmailVerificationHandler{Endpoint: EmailVerificationEndpoint, client: c, cfg: cfg}
}

type emailVerificationRequest struct {
	UserID   string `json:"userId"`
	Code     string `json:"code"`
	ReturnTo string `json:"returnTo"`
}

func (h *EmailVerificationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context()).WithName("emailVerificationHandler")

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req emailVerificationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.UserID == "" || req.Code == "" || req.ReturnTo == "" {
		http.Error(w, "userId, code and returnTo are required", http.StatusBadRequest)
		return
	}

	// Parsed once here and reused for the action URL, so the value the allowlist
	// approved is the value we build the link from.
	returnTo, err := url.Parse(req.ReturnTo)
	if err != nil || returnTo.Scheme == "" || returnTo.Host == "" || !h.originAllowed(returnTo) {
		// Deliberately does not echo the value: this is the phishing guard, and the
		// rejected origin is attacker-controlled input.
		log.Info("Rejected returnTo outside the allowlist", "userId", req.UserID)
		http.Error(w, "returnTo is not allowed", http.StatusBadRequest)
		return
	}

	user, err := h.userWithRetry(r.Context(), req.UserID)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("No User for verification mail", "userId", req.UserID)
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		log.Error(err, "Failed to read User", "userId", req.UserID)
		http.Error(w, "failed to read user", http.StatusInternalServerError)
		return
	}

	emailName, err := h.createEmail(r.Context(), user, req, actionURLFor(returnTo, req.Code, req.UserID))
	if err != nil {
		// The code sits in this Email's Variables, and an apiserver rejection can echo a
		// submitted value straight back — so for those log only the fixed-vocabulary Reason
		// and status code. A transport failure never reached admission and cannot quote the
		// request, so it is logged whole: it is the only thing that explains a timeout.
		//
		// Discriminate on the type, not on Reason being empty. ReasonForError returns ""
		// for BOTH a transport error and a StatusError whose Reason is unset (a bare 500),
		// and that second one must still be redacted.
		var status apierrors.APIStatus
		if errors.As(err, &status) {
			s := status.Status()
			log.Error(fmt.Errorf("apiserver rejected Email create: %q (code %d)", s.Reason, s.Code),
				"Failed to create verification Email", "userId", req.UserID)
		} else {
			log.Error(err, "Failed to create verification Email", "userId", req.UserID)
		}
		http.Error(w, "failed to create email", http.StatusInternalServerError)
		return
	}

	log.Info("Created verification Email", "userId", req.UserID, "emailName", emailName)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// originAllowed is the phishing guard: without it a compromised auth-ui could have
// us mail a real, working code pointing at any domain. Compares scheme+host rather
// than a prefix, which would admit "https://auth.example.test.evil.com".
func (h *EmailVerificationHandler) originAllowed(u *url.URL) bool {
	for _, allowed := range h.cfg.AllowedOrigins {
		a, err := url.Parse(allowed)
		if err != nil {
			continue
		}
		// Host is compared case-insensitively: url.Parse lowercases the scheme but
		// not the host, so a capitalised allowlist entry would otherwise match nothing.
		if strings.EqualFold(u.Scheme, a.Scheme) && strings.EqualFold(u.Host, a.Host) {
			return true
		}
	}
	return false
}

// userWithRetry absorbs the signup race: create-user-account provisions the milo User
// from the same Zitadel event that produced this code, so the User can be moments
// behind the request.
//
// Backoff is linear rather than exponential: a caller is blocked on this response.
func (h *EmailVerificationHandler) userWithRetry(ctx context.Context, id string) (*iamv1alpha1.User, error) {
	attempts := h.cfg.UserLookupAttempts
	if attempts < 1 {
		attempts = 1
	}
	baseWait := h.cfg.UserLookupBaseWait
	if baseWait < 0 {
		baseWait = 0
	}

	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		user := &iamv1alpha1.User{}
		err := h.client.Get(ctx, client.ObjectKey{Name: id}, user)
		if err == nil {
			return user, nil
		}
		last = err
		if !apierrors.IsNotFound(err) {
			return nil, err
		}
		// No sleep after the last attempt — the caller is waiting on this response,
		// and the final wait buys nothing but latency on the 404 path.
		if attempt == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * baseWait):
		}
	}
	return nil, last
}

// createEmail creates the Email and returns its name.
//
// The name is derived from userID+code so a retried POST addresses the same object:
// auth-ui retries on timeout, and without this each retry sends another mail. Hashed
// rather than composed, because an object name is not a place to put a live code.
func (h *EmailVerificationHandler) createEmail(
	ctx context.Context,
	user *iamv1alpha1.User,
	req emailVerificationRequest,
	actionURL string,
) (string, error) {
	displayName := strings.TrimSpace(user.Spec.GivenName + " " + user.Spec.FamilyName)
	if displayName == "" {
		displayName = user.Spec.Email
	}

	expiryMinutes := h.cfg.ExpiryMinutes
	if expiryMinutes <= 0 {
		expiryMinutes = defaultExpiryMinutes
	}

	sum := sha256.Sum256([]byte(req.UserID + ":" + req.Code))
	name := "email-verification-" + hex.EncodeToString(sum[:])[:16]

	email := &notificationv1alpha1.Email{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Email",
			APIVersion: "notification.miloapis.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: h.cfg.NotificationNamespace,
		},
		Spec: notificationv1alpha1.EmailSpec{
			TemplateRef: notificationv1alpha1.TemplateReference{Name: h.cfg.TemplateName},
			// Literal address: the User is already read above, so UserRef would
			// only have the pipeline resolve the same record again.
			Recipient: notificationv1alpha1.EmailRecipient{EmailAddress: user.Spec.Email},
			Variables: []notificationv1alpha1.EmailVariable{
				{Name: "UserName", Value: displayName},
				{Name: "Code", Value: req.Code},
				{Name: "ActionUrl", Value: actionURL},
				{Name: "ExpiryMinutes", Value: strconv.Itoa(expiryMinutes)},
			},
			Priority: notificationv1alpha1.EmailPriorityHigh,
		},
	}

	if err := h.client.Create(ctx, email); err != nil {
		// Already exists means an earlier POST with this same userID+code already
		// queued the mail. Report success: the caller wanted a mail sent, and one was.
		if apierrors.IsAlreadyExists(err) {
			return name, nil
		}
		return "", err
	}
	return name, nil
}

// actionURLFor adds the code and userId to an already-validated returnTo. It takes the
// parsed URL rather than the raw string so the link cannot be built from anything the
// allowlist did not approve.
func actionURLFor(returnTo *url.URL, code, userID string) string {
	u := *returnTo
	q := u.Query()
	q.Set("code", code)
	q.Set("userId", userID)
	u.RawQuery = q.Encode()
	return u.String()
}
