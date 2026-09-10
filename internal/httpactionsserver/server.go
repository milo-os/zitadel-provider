package httpactionsserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"go.miloapis.com/auth-provider-zitadel/internal/emailverified"
	"go.miloapis.com/auth-provider-zitadel/internal/userprovision"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

// ServerConfig holds configuration for the HTTP actions server
// It mirrors the previous ActionsServerConfig that lived under cmd/actionsserver.
type ServerConfig struct {
	Addr                       string
	CertFile                   string
	KeyFile                    string
	DisableHTTP2               bool
	Kubeconfig                 string
	SigningKey                 string
	DisableSignatureValidation bool
	// SuspiciousLoginEmailTemplate is the name of the EmailTemplate cluster resource
	// used to notify users of suspicious login activity.
	SuspiciousLoginEmailTemplate string
	// PasskeyAddedEmailTemplate is the name of the EmailTemplate cluster
	// resource used to notify users when a passkey is enrolled on their
	// account. Defaults to the conventional generated name (same scheme as
	// SuspiciousLoginEmailTemplate and milo's notification templates); an
	// empty value disables the notification (unconfigured means skip).
	PasskeyAddedEmailTemplate string
	// PasskeyRemovedEmailTemplate is the EmailTemplate used to notify users
	// when a passkey is removed from their account. An empty value disables the
	// notification (unconfigured means skip), matching
	// PasskeyAddedEmailTemplate.
	PasskeyRemovedEmailTemplate string
	// NotificationNamespace is the namespace in which Email resources are created.
	NotificationNamespace string
	// GraphQLGatewayURL is the endpoint of the internal GraphQL gateway used
	// for IP geolocation and user-agent parsing.
	// When empty, those lookups are skipped and fallbacks are used instead.
	GraphQLGatewayURL string
	// GraphQLGatewayCACertFile is the path to a PEM-encoded CA certificate
	// used to verify the gateway's TLS certificate. When empty the system
	// cert pool is used (sufficient if the CA is already trusted by the OS).
	GraphQLGatewayCACertFile string
	// IdpIntentUserLookupAttempts is how many times to retry fetching the Milo
	// User when idpintent.succeeded arrives before user.human.added creates it.
	IdpIntentUserLookupAttempts int
	// IdpIntentUserLookupBaseWait is the initial backoff between those retries.
	IdpIntentUserLookupBaseWait time.Duration
}

type ValidateSignatureFunc func(payload []byte, header string, signingKey string) error

// NewServerConfig returns a config initialised with sensible defaults.
func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		Addr:                         ":8082",
		DisableSignatureValidation:   false,
		SuspiciousLoginEmailTemplate: "emailtemplates.notification.miloapis.com-usersuspiciousemailtemplate",
		PasskeyAddedEmailTemplate:    "emailtemplates.notification.miloapis.com-userpasskeyaddedemailtemplate",
		NotificationNamespace:        "milo-system",
		GraphQLGatewayURL:            "https://graphql-gateway.graphql-gateway.svc.cluster.local:4000/graphql",
		GraphQLGatewayCACertFile:     "/etc/ssl/certs/datum-ca.crt",
		IdpIntentUserLookupAttempts:  8,
		IdpIntentUserLookupBaseWait:  250 * time.Millisecond,
	}
}

// Server represents the HTTP actions server with Kubernetes client
type Server struct {
	config            *ServerConfig
	k8sClient         client.Client
	validateSignature ValidateSignatureFunc

	// httpClient is used for outbound HTTP calls (e.g. geolocation lookups).
	httpClient *http.Client

	// mu guards zitadelClient, which may be installed asynchronously by a
	// background initializer after the server has already started.
	mu            sync.RWMutex
	zitadelClient zitadel.API
}

// SetZitadelClient atomically installs the Zitadel SDK client. It is safe for
// concurrent use and is called by the background initializer once Zitadel
// becomes reachable.
func (s *Server) SetZitadelClient(c zitadel.API) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zitadelClient = c
}

// zitadelAPI returns the current Zitadel SDK client, or nil if it has not been
// initialized yet.
func (s *Server) zitadelAPI() zitadel.API {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.zitadelClient
}

// NewServer creates a new HTTP actions server instance
func NewServer(cfg *ServerConfig, k8sClient client.Client, validateSignatureFunc ValidateSignatureFunc, zitadelClient zitadel.API) *Server {
	log := logf.Log.WithName("httpactionsserver")
	log.Info("Creating new HTTP actions server", "addr", cfg.Addr, "tlsEnabled", cfg.CertFile != "" && cfg.KeyFile != "")
	return &Server{
		config:            cfg,
		k8sClient:         k8sClient,
		validateSignature: validateSignatureFunc,
		zitadelClient:     zitadelClient,
		httpClient:        buildHTTPClient(log, cfg.GraphQLGatewayCACertFile),
	}
}

// buildHTTPClient creates an http.Client that trusts the cluster CA cert at
// caCertFile (if the file exists) in addition to the system cert pool. When
// the file is absent the default system pool is used, which is correct for
// environments where the CA is already trusted at the OS level.
func buildHTTPClient(log interface{ Info(string, ...any) }, caCertFile string) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if caCertFile != "" {
		pem, err := os.ReadFile(caCertFile)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Info("Could not read gateway CA cert file; using system cert pool", "file", caCertFile, "err", err)
			}
		} else {
			pool, err := x509.SystemCertPool()
			if err != nil {
				pool = x509.NewCertPool()
			}
			if pool.AppendCertsFromPEM(pem) {
				transport.TLSClientConfig = &tls.Config{RootCAs: pool}
				log.Info("Loaded gateway CA cert", "file", caCertFile)
			} else {
				log.Info("gateway CA cert file contained no valid PEM blocks; using system cert pool", "file", caCertFile)
			}
		}
	}

	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
}

type EventType string

const (
	EventTypeUserHumanSelfRegistered EventType = "user.human.selfregistered"
	EventTypeUserHumanAdded          EventType = "user.human.added"
)

var SupportedUserCreationEvents = []EventType{EventTypeUserHumanSelfRegistered, EventTypeUserHumanAdded}

// createUserAccountRequest represents the expected JSON payload for the endpoint.
// It matches the structure provided by Zitadel actions.
type createUserAccountRequest struct {
	AggregateID   string    `json:"aggregateID"`
	AggregateType string    `json:"aggregateType"`
	ResourceOwner string    `json:"resourceOwner"`
	InstanceID    string    `json:"instanceID"`
	Version       string    `json:"version"`
	Sequence      int       `json:"sequence"`
	EventType     EventType `json:"event_type"`
	CreatedAt     string    `json:"created_at"`
	UserID        string    `json:"userID"`
	EventPayload  struct {
		UserName          string `json:"userName"`
		FirstName         string `json:"firstName"`
		LastName          string `json:"lastName"`
		DisplayName       string `json:"displayName"`
		PreferredLanguage string `json:"preferredLanguage"`
		Email             string `json:"email"`
		EncodedHash       string `json:"encodedHash"`
		UserAgentID       string `json:"userAgentID"`
	} `json:"event_payload"`
}

// Start starts the HTTP(S) server
func (s *Server) Start() error {
	log := logf.Log.WithName("httpactionsserver")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/actions/create-user-account", s.createUserAccountHandler)
	mux.HandleFunc("/v1/actions/customize-jwt", s.customizeJwtHandler)
	mux.HandleFunc("/v1/actions/idp-intent-succeeded", s.idpIntentSucceededHandler)
	mux.HandleFunc("/v1/actions/session-added", s.sessionAddedHandler)
	mux.HandleFunc("/v1/actions/passkey-added", s.passkeyAddedHandler)
	mux.HandleFunc("/v1/actions/passkey-removed", s.passkeyRemovedHandler)
	mux.HandleFunc("/v1/actions/email-verified", s.emailVerifiedHandler)

	srv := &http.Server{
		Addr:    s.config.Addr,
		Handler: mux,
	}

	// If TLS cert and key are provided, serve HTTPS
	if s.config.CertFile != "" && s.config.KeyFile != "" {
		log.Info("Configuring TLS",
			"certFile", s.config.CertFile,
			"keyFile", s.config.KeyFile,
			"disableHTTP2", s.config.DisableHTTP2)

		if s.config.DisableHTTP2 {
			// Disable HTTP/2 by restricting the advertised protocols to http/1.1
			srv.TLSConfig = &tls.Config{NextProtos: []string{"http/1.1"}}
			log.Info("HTTP/2 disabled")
		}
		log.Info("Starting HTTPS server", "addr", s.config.Addr)
		return srv.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile)
	}

	log.Info("Starting HTTP server", "addr", s.config.Addr)
	return srv.ListenAndServe()
}

// createUserAccountHandler handles the POST request to create a user account.
func (s *Server) createUserAccountHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context()).WithName("createUserAccountHandler")
	log.Info("Handling create-user-account request", "method", r.Method, "remoteAddr", r.RemoteAddr)

	if r.Method != http.MethodPost {
		log.Error(nil, "Method not allowed", "method", r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error(err, "Failed to read request body")
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := s.validateSignature(bodyBytes, r.Header.Get("Zitadel-Signature"), s.config.SigningKey); err != nil {
		log.Error(err, "Signature validation failed")
		http.Error(w, fmt.Sprintf("signature validation failed: %v", err), http.StatusUnauthorized)
		return
	}
	log.V(1).Info("Request signature validated successfully")

	var req createUserAccountRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		log.Error(err, "Failed to unmarshal request body")
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	log.V(1).Info("Request body unmarshaled successfully")
	// Validate event type
	if !slices.Contains(SupportedUserCreationEvents, req.EventType) {
		log.Error(nil, "Unsupported event type", "eventType", req.EventType)
		http.Error(w, fmt.Sprintf("unsupported event type: %s", req.EventType), http.StatusBadRequest)
		return
	}

	log.Info("Processing user account creation",
		"eventType", req.EventType,
		"email", req.EventPayload.Email,
		"zitadelUserId", req.UserID,
	)

	user := userprovision.NewUser(req.AggregateID, req.EventPayload.Email, req.EventPayload.FirstName, req.EventPayload.LastName)
	created, err := userprovision.EnsureUser(r.Context(), s.k8sClient, user)
	if err != nil {
		log.Error(err, "Failed to create user resource",
			"zitadelUserId", req.UserID,
			"email", req.EventPayload.Email,
		)
		http.Error(w, fmt.Sprintf("failed to create user resource: %v", err), http.StatusInternalServerError)
		return
	}
	if !created {
		log.Info("User resource already exists", "zitadelUserId", req.UserID)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("already exists"))
		return
	}

	log.Info("Successfully created user resource",
		"userName", req.UserID,
		"email", req.EventPayload.Email,
	)

	// C11: record the initial EmailVerification field so the value is right from the
	// first reconcile — IdP-created users are verified at creation and must not wait
	// for a sweep to be welcomed. Best effort: never fail the provisioning ack over
	// it, because Zitadel would retry the whole create. A miss self-heals on the next
	// sweep, which reconciles the same field from ListHumanUsers.
	if zc := s.zitadelAPI(); zc != nil {
		if zu, err := zc.GetUserByID(r.Context(), user.Name); err == nil {
			if _, err := emailverified.Set(r.Context(), s.k8sClient, user.Name, zu.IsEmailVerified); err != nil {
				log.Error(err, "initial EmailVerification skipped; sweeper will reconcile", "userName", user.Name)
			}
		} else {
			log.Error(err, "initial EmailVerification skipped; sweeper will reconcile", "userName", user.Name)
		}
	}

	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte("created"))
}

type CustomizeJwtHandlerResponse struct {
	SetUserMetadata []*Metadata    `json:"set_user_metadata,omitempty"`
	AppendClaims    []*AppendClaim `json:"append_claims,omitempty"`
}

// CustomizeJWTRequest is the PARTIAL request body for the customize-jwt endpoint.
// It is used to extract the necessary information from the request body.
type CustomizeJwtHandlerRequest struct {
	UserInfo struct {
		Sub string `json:"sub"`
	} `json:"userinfo"`
	Function string `json:"function"`
	User     struct {
		Username string `json:"username"`
		Human    *struct {
			Email string `json:"email"`
		} `json:"human,omitempty"`
	} `json:"user"`
}

// IdpIntentSucceededRequest models JUST the fields we need from an idpintent.succeeded Zitadel payload.
type IdpIntentSucceededRequest struct {
	EventType    string `json:"event_type"`
	UserID       string `json:"userId"`
	EventPayload struct {
		IDPUser    string `json:"idpUser"`
		IDPIdToken string `json:"idpIdToken,omitempty"`
		UserID     string `json:"userId,omitempty"`
	} `json:"event_payload"`
}

// IDPUserData represents the decoded idpUser data from identity providers
type IDPUserData struct {
	User struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		FamilyName    string `json:"family_name"`
		GivenName     string `json:"given_name"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		Sub           string `json:"sub"`
		// GitHub specific fields
		AvatarURL string `json:"avatar_url,omitempty"`
		Login     string `json:"login,omitempty"`
	} `json:"User"`
}

type Metadata struct {
	Key   string `json:"key"`
	Value []byte `json:"value"`
}

type AppendClaim struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

// customizeJwtHandler is a custom JWT handler that adds a custom email address claim to the JWT.
func (s *Server) customizeJwtHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context()).WithName("customizeJwtHandler")
	log.Info("Handling customize-jwt request", "method", r.Method, "remoteAddr", r.RemoteAddr)

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error(err, "Failed to read request body")
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	log.V(1).Info("Successfully read request body")

	if err := s.validateSignature(bodyBytes, r.Header.Get("Zitadel-Signature"), s.config.SigningKey); err != nil {
		log.Error(err, "Signature validation failed")
		http.Error(w, fmt.Sprintf("signature validation failed: %v", err), http.StatusUnauthorized)
		return
	}
	log.V(1).Info("Request signature validated successfully")

	var request CustomizeJwtHandlerRequest
	if err := json.Unmarshal(bodyBytes, &request); err != nil {
		log.Error(err, "Failed to unmarshal request body")
		http.Error(w, "Failed to parse request body", http.StatusBadRequest)
		return
	}
	log.V(1).Info("Successfully unmarshaled request body", "function", request.Function, "userSub", request.UserInfo.Sub)

	if request.Function != "function/preuserinfo" && request.Function != "function/preaccesstoken" {
		log.Error(nil, "Unsupported function", "function", request.Function)
		http.Error(w, fmt.Sprintf("unsupported function: %s", request.Function), http.StatusBadRequest)
		return
	}
	log.V(1).Info("Validated function type", "function", request.Function)

	// Determine email based on user type
	var email string
	if request.User.Human != nil {
		email = request.User.Human.Email
		log.V(1).Info("Processing human user", "email", email)
	} else {
		email = request.User.Username
		log.V(1).Info("Processing machine user", "email", email)
	}

	resp := &CustomizeJwtHandlerResponse{
		SetUserMetadata: []*Metadata{
			{Key: "key", Value: []byte("value")},
		},
		AppendClaims: []*AppendClaim{
			{Key: "email", Value: email},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		log.Error(err, "Failed to marshal response")
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	log.Info("Successfully processed customize-jwt request", "userSub", request.UserInfo.Sub, "email", email)

	_, err = w.Write(data)
	if err != nil {
		log.Error(err, "Failed to write response")
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	log.Info("Successfully wrote response")
}

// idpIntentSucceededHandler processes the idpintent.succeeded action to capture the IDP provider and avatar URL.
func (s *Server) idpIntentSucceededHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context()).WithName("idpIntentSucceededHandler")

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error(err, "Failed to read request body")
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	if err := s.validateSignature(bodyBytes, r.Header.Get("Zitadel-Signature"), s.config.SigningKey); err != nil {
		log.Error(err, "Signature validation failed")
		http.Error(w, fmt.Sprintf("signature validation failed: %v", err), http.StatusUnauthorized)
		return
	}

	var req IdpIntentSucceededRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		log.Error(err, "Failed to parse body")
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	if req.EventType != "idpintent.succeeded" || req.EventPayload.IDPUser == "" {
		log.Error(nil, "Unexpected event type", "eventType", req.EventType)
		http.Error(w, "unexpected event", http.StatusBadRequest)
		return
	}

	// Decode idpUser JSON
	raw, err := base64.StdEncoding.DecodeString(req.EventPayload.IDPUser)
	if err != nil {
		log.Error(err, "Failed to decode idpUser")
		http.Error(w, "invalid idpUser", http.StatusBadRequest)
		return
	}

	// Detect provider & avatar generically (supports Google & GitHub)
	idpProvider, avatarURL, perr := parseIDPUserData(raw)
	if perr != nil {
		log.Error(perr, "Failed to parse idpUser JSON")
		http.Error(w, "invalid idpUser data", http.StatusBadRequest)
		return
	}

	userID := miloUserIDFromIdpIntent(req)
	if userID == "" {
		log.Error(nil, "User ID not found in idpintent.succeeded payload")
		http.Error(w, "userID not found in payload", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	current, err := s.getUserWithRetry(ctx, userID)
	if err != nil {
		log.Error(err, "Failed to get User resource", "userId", userID)
		if apierrors.IsNotFound(err) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to get user", http.StatusInternalServerError)
		return
	}
	original := current.DeepCopy()

	current.Status.AvatarURL = avatarURL
	current.Status.LastLoginProvider = idpProvider

	fieldManagerName := "idp-intent-succeeded"
	if err := s.k8sClient.Status().Patch(ctx, current, client.MergeFrom(original), client.FieldOwner(fieldManagerName)); err != nil {
		log.Error(err, "Failed to patch User status")
		http.Error(w, "failed to patch user", http.StatusInternalServerError)
		return
	}

	log.Info("Processed idpintent.succeeded", "idpProvider", idpProvider, "avatarURL", avatarURL, "userId", userID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("success"))
}

func miloUserIDFromIdpIntent(req IdpIntentSucceededRequest) string {
	if id := req.EventPayload.UserID; id != "" {
		return id
	}
	return req.UserID
}

func (s *Server) getUserWithRetry(ctx context.Context, userID string) (*iammiloapiscomv1alpha1.User, error) {
	current := &iammiloapiscomv1alpha1.User{}
	var err error

	attempts := s.config.IdpIntentUserLookupAttempts
	if attempts < 1 {
		attempts = 1
	}
	baseWait := s.config.IdpIntentUserLookupBaseWait
	if baseWait < 0 {
		baseWait = 0
	}

	for attempt := 0; attempt < attempts; attempt++ {
		err = s.k8sClient.Get(ctx, client.ObjectKey{Name: userID}, current)
		if err == nil {
			return current, nil
		}
		if !apierrors.IsNotFound(err) || attempt == attempts-1 {
			return nil, err
		}
		time.Sleep(baseWait * time.Duration(1<<attempt))
	}

	return nil, err
}

// parseIDPUserData inspects the raw json of idpUser (base64 decoded) and
// returns provider and avatar URL best effort without relying on rigid structs.
func parseIDPUserData(raw []byte) (iammiloapiscomv1alpha1.AuthProvider, string, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", "", err
	}

	// Google format: {"User": {"picture": "..."}}
	if user, ok := m["User"].(map[string]interface{}); ok {
		if pic, ok := user["picture"].(string); ok && pic != "" {
			return iammiloapiscomv1alpha1.AuthProviderGoogle, pic, nil
		}
		if avatar, ok := user["avatar_url"].(string); ok && avatar != "" {
			return iammiloapiscomv1alpha1.AuthProviderGitHub, avatar, nil
		}
	}

	// GitHub format: top-level avatar_url
	if avatar, ok := m["avatar_url"].(string); ok && avatar != "" {
		return iammiloapiscomv1alpha1.AuthProviderGitHub, avatar, nil
	}

	// Also google picture could be top-level
	if pic, ok := m["picture"].(string); ok && pic != "" {
		if strings.Contains(pic, "googleusercontent.com") {
			return iammiloapiscomv1alpha1.AuthProviderGoogle, pic, nil
		}

	}

	return "", "", errors.New("unknown idp provider")
}
