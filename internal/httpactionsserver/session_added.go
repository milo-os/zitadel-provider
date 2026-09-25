package httpactionsserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"

	"go.miloapis.com/auth-provider-zitadel/pkg/gateway"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
)

type userAgent struct {
	IP            string `json:"ip"`
	FingerprintID string `json:"fingerprint_id"`
	Description   string `json:"description"`
}

type sessionAddedRequest struct {
	AggregateID   string `json:"aggregateID"`
	AggregateType string `json:"aggregateType"`
	ResourceOwner string `json:"resourceOwner"`
	InstanceID    string `json:"instanceID"`
	Version       string `json:"version"`
	Sequence      int    `json:"sequence"`
	EventType     string `json:"event_type"`
	CreatedAt     string `json:"created_at"`
	UserID        string `json:"userID"`
	EventPayload  struct {
		UserID    string     `json:"userID"`
		SessionID string     `json:"sessionID"`
		UserAgent *userAgent `json:"userAgent"`
	} `json:"event_payload"`
}

// sessionAddedHandler handles the session.added event to detect suspicious logins.
func (s *Server) sessionAddedHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context()).WithName("sessionAddedHandler")
	log.Info("Handling session-added request", "method", r.Method, "remoteAddr", r.RemoteAddr)

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

	var req sessionAddedRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		log.Error(err, "Failed to unmarshal request body")
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	log.V(1).Info("Request body unmarshaled successfully")

	if req.EventType != "oidc_session.added" {
		log.Error(nil, "Unsupported event type", "eventType", req.EventType)
		http.Error(w, fmt.Sprintf("unsupported event type: %s", req.EventType), http.StatusBadRequest)
		return
	}

	userID := req.EventPayload.UserID
	if userID == "" {
		log.Error(nil, "User ID not found in payload")
		http.Error(w, "userID not found in payload", http.StatusBadRequest)
		return
	}

	zClient := s.zitadelAPI()
	if zClient == nil {
		log.Error(nil, "Zitadel SDK client not configured, cannot retrieve session history")
		http.Error(w, "zitadel sdk client not configured", http.StatusServiceUnavailable)
		return
	}

	if zitadelUser, err := zClient.GetUserByID(r.Context(), userID); err == nil && zitadelUser != nil && zitadelUser.Email != "" {
		if s.applyPendingAvatarByEmail(r.Context(), log, userID, zitadelUser.Email, "session-added") {
			log.Info("Applied pending avatar during session added", "userId", userID, "email", zitadelUser.Email)
		}
	}

	var currentIP string
	var currentUserAgent string
	var currentFingerprint string
	ua := req.EventPayload.UserAgent
	if ua != nil {
		currentIP = ua.IP
		currentUserAgent = ua.Description
		currentFingerprint = ua.FingerprintID
	}

	log.Info("Checking sessions for user", "userId", userID)
	sessions, err := zClient.ListSessions(r.Context(), userID)
	if err != nil {
		log.Error(err, "Failed to list sessions from Zitadel", "userId", userID)
		http.Error(w, fmt.Sprintf("failed to list sessions: %v", err), http.StatusInternalServerError)
		return
	}

	sessionID := req.EventPayload.SessionID
	if sessionID == "" {
		sessionID = req.AggregateID
	}

	if current := findSessionByID(sessions, sessionID); current != nil && current.PasskeyVerified {
		log.Info("Session authenticated via passkey; exempting from suspicious-login check", "userId", userID, "sessionId", sessionID)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
		return
	}

	previousSessions := getPreviousSessions(sessions, sessionID)
	if len(previousSessions) > 0 {
		if isSuspiciousLogin(log, previousSessions, currentIP, currentUserAgent, currentFingerprint) {
			handleSuspiciousLogin(r.Context(), log, s, userID, req.CreatedAt, currentIP, currentUserAgent)
		} else {
			log.Info("Login is not suspicious", "userId", userID)
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("success"))
}

// findSessionByID returns a pointer to the session with the given ID within
// sessions, or nil if absent. Used to recover the current session's factor
// detail (e.g. PasskeyVerified) from the full list already fetched via
// ListSessions — the session.added webhook payload itself carries no
// factor information.
func findSessionByID(sessions []zitadel.Session, id string) *zitadel.Session {
	for i := range sessions {
		if sessions[i].ID == id {
			return &sessions[i]
		}
	}
	return nil
}

// getPreviousSessions filters the list of sessions to return all sessions other than the current one.
func getPreviousSessions(sessions []zitadel.Session, currentSessionID string) []zitadel.Session {
	previous := make([]zitadel.Session, 0, len(sessions))
	for i := range sessions {
		if sessions[i].ID == currentSessionID {
			continue
		}
		previous = append(previous, sessions[i])
	}
	return previous
}

// isSuspiciousLogin evaluates the current login details against the history of previous sessions.
func isSuspiciousLogin(log logr.Logger, previousSessions []zitadel.Session, currentIP, currentUserAgent, currentFingerprint string) bool {
	if len(previousSessions) == 0 {
		return false
	}

	ipSeen := false
	userAgentSeen := false
	fingerprintSeen := false

	for _, sess := range previousSessions {
		if sess.IP == currentIP {
			ipSeen = true
		}
		if sess.UserAgent == currentUserAgent {
			userAgentSeen = true
		}
		if currentFingerprint != "" && sess.FingerprintID == currentFingerprint {
			fingerprintSeen = true
		}
	}

	isNewIP := currentIP != "" && !ipSeen
	isNewUserAgent := currentUserAgent != "" && !userAgentSeen
	isNewFingerprint := currentFingerprint != "" && !fingerprintSeen

	log.Info("Comparing current login against session history",
		"currentIP", currentIP, "ipSeen", ipSeen, "isNewIP", isNewIP,
		"currentUserAgent", currentUserAgent, "userAgentSeen", userAgentSeen, "isNewUserAgent", isNewUserAgent,
		"currentFingerprint", currentFingerprint, "fingerprintSeen", fingerprintSeen, "isNewFingerprint", isNewFingerprint,
	)

	return isNewIP || isNewUserAgent || isNewFingerprint
}

// handleSuspiciousLogin logs the suspicious login and sends a notification email to the user.
func handleSuspiciousLogin(ctx context.Context, log logr.Logger, s *Server, userID, signInTime, ip, userAgent string) {
	device, browser := resolveUserAgent(ctx, log, s, userAgent)
	location := resolveLocation(ctx, log, s, ip)

	log.Info("Suspicious login detected", "userId", userID, "ip", ip, "device", device, "browser", browser, "location", location)

	if err := sendSuspiciousLoginEmail(ctx, log, s, userID, signInTime, ip, device, browser, location); err != nil {
		log.Error(err, "Failed to send suspicious login notification email", "userId", userID)
	}
}

// sendSuspiciousLoginEmail looks up the User resource by Zitadel userID and
// creates an Email resource that the notification system delivers.
func sendSuspiciousLoginEmail(ctx context.Context, log logr.Logger, s *Server, userID, signInTime, ip, device, browser, location string) error {
	if s.config.SuspiciousLoginEmailTemplate == "" {
		log.Info("Suspicious login email template not configured; skipping notification")
		return nil
	}

	// Fetch the User resource — its name is the Zitadel aggregate ID.
	user := &iamv1alpha1.User{}
	if err := s.k8sClient.Get(ctx, client.ObjectKey{Name: userID}, user); err != nil {
		return fmt.Errorf("failed to get user %q: %w", userID, err)
	}

	displayName := strings.TrimSpace(user.Spec.GivenName + " " + user.Spec.FamilyName)
	if displayName == "" {
		displayName = user.Spec.Email
	}

	// Parse signInTime into a human-readable format; fall back to the raw string.
	signInDisplay := signInTime
	if t, err := time.Parse(time.RFC3339Nano, signInTime); err == nil {
		signInDisplay = t.UTC().Format("Jan 2, 2006 at 15:04 UTC")
	}

	email := &notificationv1alpha1.Email{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Email",
			APIVersion: "notification.miloapis.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("suspicious-login-%s", uuid.NewUUID()),
			Namespace: s.config.NotificationNamespace,
		},
		Spec: notificationv1alpha1.EmailSpec{
			TemplateRef: notificationv1alpha1.TemplateReference{
				Name: s.config.SuspiciousLoginEmailTemplate,
			},
			Recipient: notificationv1alpha1.EmailRecipient{
				UserRef: notificationv1alpha1.EmailUserReference{
					Name: user.Name,
				},
			},
			Variables: []notificationv1alpha1.EmailVariable{
				{Name: "UserName", Value: displayName},
				{Name: "Email", Value: user.Spec.Email},
				{Name: "Location", Value: location},
				{Name: "SignInTime", Value: signInDisplay},
				{Name: "Browser", Value: browser},
				{Name: "Device", Value: device},
				{Name: "IpAddress", Value: ip},
			},
			Priority: notificationv1alpha1.EmailPriorityHigh,
		},
	}

	if err := s.k8sClient.Create(ctx, email); err != nil {
		return fmt.Errorf("failed to create suspicious login Email resource: %w", err)
	}

	log.Info("Suspicious login notification email created", "userId", userID, "emailName", email.Name)
	return nil
}

// resolveLocation returns a human-readable location string for ip by querying
// the GraphQL gateway. If the gateway URL is not configured, the IP is
// unreachable, or no record is found, it falls back to the raw IP address so
// the email is always sent with something meaningful.
func resolveLocation(ctx context.Context, log logr.Logger, s *Server, ip string) string {
	if s.config.GraphQLGatewayURL == "" || ip == "" {
		return ip
	}

	geo, err := gateway.LookupIP(ctx, s.httpClient, s.config.GraphQLGatewayURL, ip)
	if err != nil {
		log.Error(err, "Failed to resolve geolocation; falling back to raw IP", "ip", ip)
		return ip
	}
	if geo == nil || geo.Formatted == "" {
		return ip
	}

	log.V(1).Info("Resolved geolocation", "ip", ip, "location", geo.Formatted)
	return geo.Formatted
}

// resolveUserAgent queries the GraphQL gateway to parse ua into device and
// browser strings. Falls back to the local parseDevice/parseBrowser helpers
// when the gateway URL is unconfigured, ua is empty, or the call fails.
func resolveUserAgent(ctx context.Context, log logr.Logger, s *Server, ua string) (device, browser string) {
	if s.config.GraphQLGatewayURL != "" && ua != "" {
		parsed, err := gateway.ParseUserAgent(ctx, s.httpClient, s.config.GraphQLGatewayURL, ua)
		if err != nil {
			log.Error(err, "Failed to parse user agent via gateway; using local fallback", "userAgent", ua)
		} else if parsed != nil {
			log.V(1).Info("Parsed user agent via gateway", "browser", parsed.Browser, "os", parsed.OS)
			return parsed.OS, parsed.Browser
		}
	}
	return parseDevice(ua), parseBrowser(ua)
}

func parseDevice(ua string) string {
	uaLower := strings.ToLower(ua)
	if strings.Contains(uaLower, ",") {
		parts := strings.Split(uaLower, ",")
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			switch trimmed {
			case "iphone":
				return "iPhone"
			case "ipad":
				return "iPad"
			case "android":
				return "Android Device"
			case "macintosh", "mac os", "macos", "mac os x":
				return "Mac"
			case "windows":
				return "Windows PC"
			case "linux":
				return "Linux PC"
			}
		}
	}

	if strings.Contains(uaLower, "iphone") {
		return "iPhone"
	}
	if strings.Contains(uaLower, "ipad") {
		return "iPad"
	}
	if strings.Contains(uaLower, "android") {
		return "Android Device"
	}
	if strings.Contains(uaLower, "macintosh") || strings.Contains(uaLower, "mac os") || strings.Contains(uaLower, "macos") {
		return "Mac"
	}
	if strings.Contains(uaLower, "windows") {
		return "Windows PC"
	}
	if strings.Contains(uaLower, "linux") {
		return "Linux PC"
	}
	return "Unknown Device"
}

func parseBrowser(ua string) string {
	uaLower := strings.ToLower(ua)
	if strings.Contains(uaLower, ",") {
		parts := strings.Split(uaLower, ",")
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			switch trimmed {
			case "firefox", "fxios":
				return "Firefox"
			case "edge", "edg":
				return "Edge"
			case "opera", "opr":
				return "Opera"
			case "chrome", "crios":
				return "Chrome"
			case "safari":
				return "Safari"
			}
		}
	}

	if strings.Contains(uaLower, "firefox/") || strings.Contains(uaLower, "fxios/") {
		return "Firefox"
	}
	if strings.Contains(uaLower, "edg/") || strings.Contains(uaLower, "edge/") {
		return "Edge"
	}
	if strings.Contains(uaLower, "opr/") || strings.Contains(uaLower, "opera/") {
		return "Opera"
	}
	if strings.Contains(uaLower, "chrome/") || strings.Contains(uaLower, "crios/") {
		return "Chrome"
	}
	if strings.Contains(uaLower, "safari/") {
		return "Safari"
	}
	return "Unknown Browser"
}
