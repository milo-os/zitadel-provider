package zitadel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	filterv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
	idpv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/idp/v2"
	objectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	orgv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/org/v2"
	sessionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/klog/v2"
)

const (
	localIdentityProviderID   = "zitadel-local"
	localIdentityProviderName = "Email"
)

type SDKConfig struct {
	// Domain is the ZITADEL gRPC/management host (host only, no scheme or path),
	// e.g. "auth.example.com".
	Domain string
	// Issuer is the full OIDC issuer URL (with scheme), used for discovery/token,
	// e.g. "https://auth.example.com".
	Issuer string
	// KeyPath is the path to the service user JSON key used to mint JWTs.
	KeyPath string
	// DefaultMachineKeyExpiration is used when a MachineAccountKey is created
	// without an explicit expiration date. ZITADEL V2 requires an expiration.
	DefaultMachineKeyExpiration time.Duration
}

type SDKClient struct {
	sess   sessionv2.SessionServiceClient
	user   userv2.UserServiceClient
	idp    idpv2.IdentityProviderServiceClient
	org    orgv2.OrganizationServiceClient
	config SDKConfig
}

// NewSDK builds a client bound to the SessionService v2.
// It validates config (including env var fallbacks) and sets up auth via a JWT
// profile token source. The ZITADEL API scope is requested; no "openid" scope is required.
func NewSDK(ctx context.Context, cfg SDKConfig) (*SDKClient, error) {
	// env fallbacks
	if cfg.Domain == "" {
		cfg.Domain = os.Getenv("ZITADEL_API")
	}
	if cfg.Issuer == "" {
		cfg.Issuer = os.Getenv("ZITADEL_ISSUER")
	} // e.g. https://auth.staging.env.datum.net
	if cfg.KeyPath == "" {
		cfg.KeyPath = os.Getenv("ZITADEL_KEY_PATH")
	}

	if cfg.Domain == "" || cfg.Issuer == "" || cfg.KeyPath == "" {
		klog.Error("NewSDK: missing required configuration (Domain, Issuer, or KeyPath)")
		return nil, errors.New("missing ZITADEL domain, issuer, or key path")
	}

	// Normalize/validate: Domain must be host[:port]; Issuer must have scheme.
	host := strings.TrimPrefix(strings.TrimPrefix(cfg.Domain, "https://"), "http://")
	if host == "" || strings.Contains(host, "/") {
		klog.Errorf("NewSDK: invalid Domain %q; must be host only (e.g. auth.example.com)", cfg.Domain)
		return nil, errors.New("domain must be host only (e.g. auth.example.com)")
	}
	// Split out an explicit port (e.g. the local stack's
	// auth.localtest.me:30000): zitadel.New always appends its own port
	// (default 443), so a port left inside the host produces an address like
	// "auth.localtest.me:30000:443" and every gRPC dial fails with "too many
	// colons in address". Staging/production domains carry no port and keep
	// the 443 default.
	var port uint16
	if h, p, err := net.SplitHostPort(host); err == nil {
		parsed, perr := strconv.ParseUint(p, 10, 16)
		if perr != nil {
			klog.Errorf("NewSDK: invalid port %q in Domain %q", p, cfg.Domain)
			return nil, fmt.Errorf("invalid port %q in domain %q", p, cfg.Domain)
		}
		host, port = h, uint16(parsed)
	}
	if !strings.HasPrefix(cfg.Issuer, "https://") && !strings.HasPrefix(cfg.Issuer, "http://") {
		klog.Errorf("NewSDK: invalid Issuer %q; must include scheme", cfg.Issuer)
		return nil, errors.New("issuer must include scheme (e.g. https://auth.example.com)")
	}

	klog.V(2).Infof("NewSDK: creating ZITADEL client (host=%q, issuer scheme ok, key path provided)", host)

	var zopts []zitadel.Option
	if port != 0 {
		zopts = append(zopts, zitadel.WithPort(port))
	}
	conf := zitadel.New(host, zopts...)

	// Use a JWT profile token source with the ZITADEL API audience scope (no "openid" needed for pure API access).
	cl, err := client.New(ctx, conf,
		client.WithAuth(func(ctx context.Context, _ string) (oauth2.TokenSource, error) {
			// We ignore the SDK-provided issuer and use the explicit cfg.Issuer instead.
			ts, err := profile.NewJWTProfileTokenSourceFromKeyFile( //nolint:staticcheck
				ctx,
				cfg.Issuer, // full https://... from config
				cfg.KeyPath,
				[]string{
					client.ScopeZitadelAPI(), // == urn:zitadel:iam:org:project:id:zitadel:aud
					// Alternatively: client.ScopeProjectID("<project-id>") to limit to a specific project.
				},
			)
			if err != nil {
				klog.Errorf("NewSDK: creating JWT profile token source failed: %v", err)
				return nil, err
			}

			// Optional: one-time fetch to surface OAuth errors early.
			if _, err := ts.Token(); err != nil {
				klog.Errorf("NewSDK: initial token retrieval failed: %v", err)
				return nil, err
			}

			klog.V(3).Info("NewSDK: JWT profile token source initialized")
			return oauth2.ReuseTokenSource(nil, ts), nil
		}),
	)
	if err != nil {
		klog.Errorf("NewSDK: client.New failed: %v", err)
		return nil, err
	}

	klog.V(2).Info("NewSDK: SessionServiceV2, UserServiceV2, IdpServiceV2, and OrganizationServiceV2 clients ready")
	return &SDKClient{
		sess:   cl.SessionServiceV2(),
		user:   cl.UserServiceV2(),
		idp:    cl.IdpServiceV2(),
		org:    cl.OrganizationServiceV2(),
		config: cfg,
	}, nil
}

func (c *SDKClient) mapZitadelSession(s *sessionv2.Session) Session {
	if s == nil {
		return Session{}
	}
	zeUA := s.GetUserAgent()
	ip := ""
	fingerprint := ""
	if zeUA != nil {
		ip = zeUA.GetIp()
		fingerprint = zeUA.GetFingerprintId()
	}
	var lastUpdated *time.Time
	if cd := s.GetChangeDate(); cd != nil {
		t := cd.AsTime()
		lastUpdated = &t
	}
	var metadata map[string]string
	if md := s.GetMetadata(); len(md) > 0 {
		metadata = make(map[string]string, len(md))
		for k, v := range md {
			metadata[k] = string(v)
		}
	}
	return Session{
		ID:              s.GetId(),
		UserID:          s.GetFactors().GetUser().GetId(),
		IP:              ip,
		FingerprintID:   fingerprint,
		CreatedAt:       toTime(s.GetCreationDate()),
		LastUpdated:     lastUpdated,
		UserAgent:       extractUserAgentString(zeUA),
		Metadata:        metadata,
		PasskeyVerified: s.GetFactors().GetWebAuthN().GetUserVerified(),
	}
}

// ListSessions retrieves sessions for a given user using the v2 SessionService.
func (c *SDKClient) ListSessions(ctx context.Context, userID string) ([]Session, error) {
	klog.V(2).Infof("ListSessions: listing sessions for userID=%q", userID)

	resp, err := c.sess.ListSessions(ctx, &sessionv2.ListSessionsRequest{
		Queries: []*sessionv2.SearchQuery{
			{Query: &sessionv2.SearchQuery_UserIdQuery{UserIdQuery: &sessionv2.UserIDQuery{Id: userID}}},
		},
	})
	if err != nil {
		klog.Errorf("ListSessions: API call failed for userID=%q: %v", userID, err)
		return nil, err
	}

	out := make([]Session, 0, len(resp.GetSessions()))
	for _, s := range resp.GetSessions() {
		out = append(out, c.mapZitadelSession(s))
	}
	klog.V(2).Infof("ListSessions: found %d session(s) for userID=%q", len(out), userID)
	return out, nil
}

// GetSession fetches a single session by ID.
func (c *SDKClient) GetSession(ctx context.Context, id string) (*Session, error) {
	klog.V(2).Infof("GetSession: fetching session id=%q", id)

	r, err := c.sess.GetSession(ctx, &sessionv2.GetSessionRequest{SessionId: id})
	if err != nil {
		klog.Errorf("GetSession: API call failed for id=%q: %v", id, err)
		return nil, err
	}
	s := r.GetSession()
	res := c.mapZitadelSession(s)
	klog.V(3).Infof("GetSession: session id=%q fetched (user=%q)", res.ID, res.UserID)
	return &res, nil
}

// DeleteSession removes a session by ID.
// The second underscore parameter is intentionally unused to keep compatibility
// with a potential wider interface; callers should pass an empty string.
func (c *SDKClient) DeleteSession(ctx context.Context, _ string, id string) error {
	klog.V(2).Infof("DeleteSession: deleting session id=%q", id)

	_, err := c.sess.DeleteSession(ctx, &sessionv2.DeleteSessionRequest{SessionId: id})
	if err != nil {
		klog.Errorf("DeleteSession: API call failed for id=%q: %v", id, err)
		return err
	}
	klog.V(2).Infof("DeleteSession: session id=%q deleted", id)
	return nil
}

// Helpers for timestamp conversion.
// toTime returns zero time when ts is nil.
func toTime(ts *pb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// ListIDPLinks retrieves all identity provider links for a given user.
func (c *SDKClient) ListIDPLinks(ctx context.Context, userID string) ([]IDPLink, error) {
	klog.V(2).Infof("ListIDPLinks: listing IDP links for userID=%q", userID)

	resp, err := c.user.ListIDPLinks(ctx, &userv2.ListIDPLinksRequest{
		UserId: userID,
	})
	if err != nil {
		klog.Errorf("ListIDPLinks: API call failed for userID=%q: %v", userID, err)
		return nil, err
	}

	out := make([]IDPLink, 0, len(resp.GetResult()))
	for _, link := range resp.GetResult() {
		idpID := link.GetIdpId()
		idpName := idpID // fallback to ID if GetIDPByID fails

		// Fetch the actual provider name from Zitadel
		idpResp, err := c.idp.GetIDPByID(ctx, &idpv2.GetIDPByIDRequest{
			Id: idpID,
		})
		if err != nil {
			klog.Warningf("ListIDPLinks: failed to get IDP name for ID %q: %v (using ID as fallback)", idpID, err)
		} else if idpResp != nil && idpResp.Idp != nil {
			idpName = idpResp.Idp.GetName()
			klog.V(3).Infof("ListIDPLinks: resolved IDP ID %q to name %q", idpID, idpName)
		}

		out = append(out, IDPLink{
			IDPID:       idpID,
			IDPName:     idpName,
			UserID:      link.GetUserId(),
			IDPUserName: link.GetUserName(),
		})
	}

	if len(out) == 0 {
		localIdentity, err := c.getLocalIdentityLink(ctx, userID)
		if err != nil {
			klog.Errorf("ListIDPLinks: failed to build local identity fallback for userID=%q: %v", userID, err)
			return nil, err
		}
		if localIdentity != nil {
			out = append(out, *localIdentity)
		}
	}
	klog.V(2).Infof("ListIDPLinks: found %d IDP link(s) for userID=%q", len(out), userID)
	return out, nil
}

func (c *SDKClient) getLocalIdentityLink(ctx context.Context, userID string) (*IDPLink, error) {
	resp, err := c.user.GetUserByID(ctx, &userv2.GetUserByIDRequest{UserId: userID})
	if err != nil {
		return nil, err
	}

	user := resp.GetUser()
	if user == nil {
		return nil, nil
	}

	username := localIdentityUsername(user)
	if username == "" {
		return nil, nil
	}

	return &IDPLink{
		IDPID:       localIdentityProviderID,
		IDPName:     localIdentityProviderName,
		UserID:      user.GetUserId(),
		IDPUserName: username,
	}, nil
}

func localIdentityUsername(user *userv2.User) string {
	if user == nil {
		return ""
	}
	if preferred := strings.TrimSpace(user.GetPreferredLoginName()); preferred != "" {
		return preferred
	}
	for _, loginName := range user.GetLoginNames() {
		if loginName = strings.TrimSpace(loginName); loginName != "" {
			return loginName
		}
	}
	return strings.TrimSpace(user.GetUsername())
}

// ListPasskeys retrieves all WebAuthn passkey credentials for a user using
// the v2 UserService. Unlike ListHumanUsers this RPC takes no pagination
// query — Zitadel returns the user's full passkey set in one call.
func (c *SDKClient) ListPasskeys(ctx context.Context, userID string) ([]Passkey, error) {
	klog.V(2).Infof("ListPasskeys: listing passkeys for userID=%q", userID)

	resp, err := c.user.ListPasskeys(ctx, &userv2.ListPasskeysRequest{UserId: userID})
	if err != nil {
		klog.Errorf("ListPasskeys: API call failed for userID=%q: %v", userID, err)
		return nil, fmt.Errorf("list passkeys: %w", err)
	}

	out := make([]Passkey, 0, len(resp.GetResult()))
	for _, p := range resp.GetResult() {
		out = append(out, Passkey{
			ID:    p.GetId(),
			Name:  p.GetName(),
			State: p.GetState().String(),
		})
	}
	klog.V(2).Infof("ListPasskeys: found %d passkey(s) for userID=%q", len(out), userID)
	return out, nil
}

// CreatePasskeyRegistrationLink asks Zitadel for a single-use passkey registration code
// (the passwordless init code) and RETURNS it instead of letting Zitadel mail it: every
// email leaves through the Datum pipeline, never Zitadel SMTP. The code is a bearer
// credential — it is never logged here.
func (c *SDKClient) CreatePasskeyRegistrationLink(ctx context.Context, userID string) (string, string, error) {
	klog.V(2).Infof("CreatePasskeyRegistrationLink: userID=%q", userID)

	resp, err := c.user.CreatePasskeyRegistrationLink(ctx, &userv2.CreatePasskeyRegistrationLinkRequest{
		UserId: userID,
		Medium: &userv2.CreatePasskeyRegistrationLinkRequest_ReturnCode{ReturnCode: &userv2.ReturnPasskeyRegistrationCode{}},
	})
	if err != nil {
		klog.Errorf("CreatePasskeyRegistrationLink: API call failed for userID=%q: %v", userID, err)
		return "", "", fmt.Errorf("create passkey registration link: %w", err)
	}

	code := resp.GetCode()
	if code == nil || code.GetCode() == "" {
		return "", "", fmt.Errorf("create passkey registration link: empty code in response")
	}
	return code.GetId(), code.GetCode(), nil
}

// ListAuthMethodTypes returns the names of the user's authentication method types.
func (c *SDKClient) ListAuthMethodTypes(ctx context.Context, userID string) ([]string, error) {
	resp, err := c.user.ListAuthenticationMethodTypes(ctx, &userv2.ListAuthenticationMethodTypesRequest{UserId: userID})
	if err != nil {
		return nil, fmt.Errorf("list authentication method types: %w", err)
	}

	out := make([]string, 0, len(resp.GetAuthMethodTypes()))
	for _, t := range resp.GetAuthMethodTypes() {
		out = append(out, t.String())
	}
	return out, nil
}

// ListUserMetadata returns every metadata entry on a Zitadel user. Values are
// returned decoded; Zitadel stores and transports them as bytes.
func (c *SDKClient) ListUserMetadata(ctx context.Context, userID string) ([]UserMetadata, error) {
	klog.V(2).Infof("ListUserMetadata: listing metadata for userID=%q", userID)

	resp, err := c.user.ListUserMetadata(ctx, &userv2.ListUserMetadataRequest{UserId: userID})
	if err != nil {
		klog.Errorf("ListUserMetadata: API call failed for userID=%q: %v", userID, err)
		return nil, fmt.Errorf("list user metadata: %w", err)
	}

	// Accessors verified against zitadel-go v3.28.0: the response field is
	// Metadata (not Result, as the sibling list calls use), and CreationDate
	// sits directly on the entry rather than under Details.
	out := make([]UserMetadata, 0, len(resp.GetMetadata()))
	for _, m := range resp.GetMetadata() {
		out = append(out, UserMetadata{
			Key:          m.GetKey(),
			Value:        string(m.GetValue()),
			CreationDate: toTime(m.GetCreationDate()),
		})
	}
	klog.V(2).Infof("ListUserMetadata: found %d entr(ies) for userID=%q", len(out), userID)
	return out, nil
}

// CreateOrganization creates a new organization in Zitadel with a custom name.
// Returns the organization ID.
func (c *SDKClient) CreateOrganization(ctx context.Context, name string) (string, error) {
	klog.V(2).Infof("CreateOrganization: creating org name=%q", name)

	resp, err := c.org.AddOrganization(ctx, &orgv2.AddOrganizationRequest{
		Name: name,
	})
	if err != nil {
		klog.Errorf("CreateOrganization: failed to create organization: %v", err)
		return "", fmt.Errorf("add organization: %w", err)
	}

	orgID := resp.GetOrganizationId()
	klog.V(2).Infof("CreateOrganization: organization created with id=%q, name=%q", orgID, name)
	return orgID, nil
}

// CreateOrganizationWithID creates a new organization in Zitadel with a custom name and ID.
// Returns the organization ID.
func (c *SDKClient) CreateOrganizationWithID(ctx context.Context, name, customOrgID string) (string, error) {
	klog.V(2).Infof("CreateOrganizationWithID: creating org name=%q with customOrgID=%q", name, customOrgID)

	resp, err := c.org.AddOrganization(ctx, &orgv2.AddOrganizationRequest{
		Name:  name,
		OrgId: &customOrgID,
	})
	if err != nil {
		klog.Errorf("CreateOrganizationWithID: failed to create organization: %v", err)
		return "", fmt.Errorf("add organization with id: %w", err)
	}

	orgID := resp.GetOrganizationId()
	klog.V(2).Infof("CreateOrganizationWithID: organization created with id=%q, name=%q", orgID, name)
	return orgID, nil
}

// AddMachineUserInOrganization creates a machine user within a specific organization.
// Returns the user ID.
func (c *SDKClient) AddMachineUserInOrganization(ctx context.Context, orgID, userID, username, displayName string) (string, error) {
	klog.V(2).Infof("AddMachineUserInOrganization: creating machine user orgID=%q, userID=%q, username=%q, displayName=%q",
		orgID, userID, username, displayName)

	// Create machine user via gRPC userv2.CreateUser with organization scope
	req := &userv2.CreateUserRequest{
		OrganizationId: orgID,
		UserId:         &userID,
		Username:       &username,
		UserType: &userv2.CreateUserRequest_Machine_{
			Machine: &userv2.CreateUserRequest_Machine{
				Name:            displayName,
				Description:     nil,
				AccessTokenType: userv2.AccessTokenType_ACCESS_TOKEN_TYPE_JWT,
			},
		},
	}

	resp, err := c.user.CreateUser(ctx, req)
	if err != nil {
		klog.Errorf("AddMachineUserInOrganization: failed to create machine user: %v", err)
		return "", fmt.Errorf("create machine user in org: %w", err)
	}

	createdUserID := resp.GetId()
	klog.V(2).Infof("AddMachineUserInOrganization: machine user created with id=%q in org=%q",
		createdUserID, orgID)
	return createdUserID, nil
}

// AddMachineKeyInOrganization registers a public key for a machine user
// within a specific organization context.
// Returns the key ID and key content (private key material from Zitadel).
func (c *SDKClient) AddMachineKeyInOrganization(ctx context.Context, orgID, userID string, publicKey []byte, expirationDate *time.Time) (keyID string, keyContent []byte, err error) {
	klog.V(2).Infof("AddMachineKeyInOrganization: orgID=%q, userID=%q", orgID, userID)

	req := &userv2.AddKeyRequest{
		UserId:    userID,
		PublicKey: publicKey,
	}
	if expirationDate != nil {
		req.ExpirationDate = pb.New(*expirationDate)
	} else {
		req.ExpirationDate = pb.New(time.Now().Add(c.config.DefaultMachineKeyExpiration))
	}

	// Set organization context in gRPC metadata using Zitadel's official middleware
	ctxWithOrg := middleware.SetOrgID(ctx, orgID)

	resp, err := c.user.AddKey(ctxWithOrg, req)
	if err != nil {
		klog.Errorf("AddMachineKeyInOrganization: failed to add key: %v", err)
		return "", nil, fmt.Errorf("add key in org: %w", err)
	}

	keyID = resp.GetKeyId()
	keyContent = resp.GetKeyContent()
	klog.V(2).Infof("AddMachineKeyInOrganization: key registered with id=%q in org=%q", keyID, orgID)
	return keyID, keyContent, nil
}

// DeleteOrganization removes a Zitadel organization.
// A gRPC NotFound error is swallowed and treated as success (idempotent).
func (c *SDKClient) DeleteOrganization(ctx context.Context, orgID string) error {
	klog.V(2).Infof("DeleteOrganization: deleting org id=%q", orgID)

	_, err := c.org.DeleteOrganization(ctx, &orgv2.DeleteOrganizationRequest{
		OrganizationId: orgID,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			klog.V(2).Infof("DeleteOrganization: org id=%q not found (idempotent)", orgID)
			return nil
		}
		klog.Errorf("DeleteOrganization: failed to delete org id=%q: %v", orgID, err)
		return fmt.Errorf("delete organization: %w", err)
	}
	klog.V(2).Infof("DeleteOrganization: org id=%q deleted", orgID)
	return nil
}

// GetOrganization retrieves a Zitadel organization by ID.
// Returns nil if the organization is not found.
// Uses ListOrganizations since there's no dedicated GetOrganizationByID endpoint.
func (c *SDKClient) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
	klog.V(2).Infof("GetOrganization: fetching org id=%q", orgID)

	resp, err := c.org.ListOrganizations(ctx, &orgv2.ListOrganizationsRequest{
		Queries: []*orgv2.SearchQuery{
			{Query: &orgv2.SearchQuery_IdQuery{
				IdQuery: &orgv2.OrganizationIDQuery{Id: orgID},
			}},
		},
	})
	if err != nil {
		klog.Errorf("GetOrganization: failed to list org id=%q: %v", orgID, err)
		return nil, fmt.Errorf("list organizations: %w", err)
	}

	if len(resp.GetResult()) == 0 {
		klog.V(2).Infof("GetOrganization: org id=%q not found", orgID)
		return nil, nil
	}

	org := resp.GetResult()[0]
	result := &Organization{
		ID:   org.GetId(),
		Name: org.GetName(),
	}
	klog.V(2).Infof("GetOrganization: org id=%q found (name=%q)", result.ID, result.Name)
	return result, nil
}

// GetMachineUserByUsername retrieves a machine user by username within an organization.
// Returns nil if the user is not found.
func (c *SDKClient) GetMachineUserByUsername(ctx context.Context, orgID, username string) (*User, error) {
	klog.V(2).Infof("GetMachineUserByUsername: fetching user username=%q in org=%q", username, orgID)

	// Search for users in the organization by username
	resp, err := c.user.ListUsers(ctx, &userv2.ListUsersRequest{
		Queries: []*userv2.SearchQuery{
			{Query: &userv2.SearchQuery_UserNameQuery{
				UserNameQuery: &userv2.UserNameQuery{UserName: username},
			}},
			{Query: &userv2.SearchQuery_OrganizationIdQuery{
				OrganizationIdQuery: &userv2.OrganizationIdQuery{OrganizationId: orgID},
			}},
		},
	})
	if err != nil {
		klog.Errorf("GetMachineUserByUsername: failed to list users: %v", err)
		return nil, fmt.Errorf("list users: %w", err)
	}

	if len(resp.GetResult()) == 0 {
		klog.V(2).Infof("GetMachineUserByUsername: user username=%q not found in org=%q", username, orgID)
		return nil, nil
	}

	user := resp.GetResult()[0]
	result := &User{
		ID:       user.GetUserId(),
		Username: localIdentityUsername(user),
		State:    user.GetState().String(),
	}
	klog.V(2).Infof("GetMachineUserByUsername: user username=%q found with id=%q in org=%q", username, result.ID, orgID)
	return result, nil
}

// GetUserByID retrieves a Zitadel user by ID.
// Returns nil if the user is not found.
func (c *SDKClient) GetUserByID(ctx context.Context, userID string) (*User, error) {
	klog.V(2).Infof("GetUserByID: fetching user id=%q", userID)

	resp, err := c.user.GetUserByID(ctx, &userv2.GetUserByIDRequest{
		UserId: userID,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			klog.V(2).Infof("GetUserByID: user id=%q not found", userID)
			return nil, nil
		}
		klog.Errorf("GetUserByID: failed to get user id=%q: %v", userID, err)
		return nil, fmt.Errorf("get user by id: %w", err)
	}

	user := resp.GetUser()
	if user == nil {
		klog.V(2).Infof("GetUserByID: user id=%q returned nil user", userID)
		return nil, nil
	}

	// Extract email from HumanUser if available; otherwise leave empty for MachineUsers
	var email string
	if humanUser := user.GetHuman(); humanUser != nil {
		if emailObj := humanUser.GetEmail(); emailObj != nil {
			email = emailObj.GetEmail()
		}
	}

	result := &User{
		ID:       user.GetUserId(),
		Username: localIdentityUsername(user),
		Email:    email,
		State:    user.GetState().String(),
	}
	klog.V(2).Infof("GetUserByID: user id=%q found (username=%q)", result.ID, result.Username)
	return result, nil
}

// ListHumanUsers returns one page of human users across all organizations,
// filtered server-side to TYPE_HUMAN and ordered ascending for stable
// pagination. Machine users are excluded; user state is intentionally NOT
// filtered — every human user in Zitadel is returned regardless of state.
// The int return is the raw number of results in the server page (before
// the defensive non-human skip) — callers MUST paginate on it, not on
// len(users), or a skipped row on a full page would end pagination early.
func (c *SDKClient) ListHumanUsers(ctx context.Context, offset uint64, limit uint32) ([]User, int, error) {
	klog.V(2).Infof("ListHumanUsers: listing human users offset=%d limit=%d", offset, limit)

	resp, err := c.user.ListUsers(ctx, &userv2.ListUsersRequest{
		Query: &objectv2.ListQuery{Offset: offset, Limit: limit, Asc: true},
		Queries: []*userv2.SearchQuery{
			{Query: &userv2.SearchQuery_TypeQuery{
				TypeQuery: &userv2.TypeQuery{Type: userv2.Type_TYPE_HUMAN},
			}},
		},
	})
	if err != nil {
		klog.Errorf("ListHumanUsers: failed to list users: %v", err)
		return nil, 0, fmt.Errorf("list human users: %w", err)
	}

	users := make([]User, 0, len(resp.GetResult()))
	for _, user := range resp.GetResult() {
		// Defensive: the server-side filter should only return humans.
		human := user.GetHuman()
		if human == nil {
			continue
		}
		users = append(users, User{
			ID:              user.GetUserId(),
			Username:        localIdentityUsername(user),
			Email:           human.GetEmail().GetEmail(),
			State:           user.GetState().String(),
			GivenName:       human.GetProfile().GetGivenName(),
			FamilyName:      human.GetProfile().GetFamilyName(),
			IsEmailVerified: human.GetEmail().GetIsVerified(),
			// toTime, not AsTime: a nil timestamp maps to the Unix EPOCH under
			// AsTime, and abandoned-account GC treats a zero CreatedAt as
			// "unknown age, skip". Epoch would read as ancient and delete it.
			CreatedAt: toTime(user.GetDetails().GetCreationDate()),
		})
	}

	raw := len(resp.GetResult())
	klog.V(2).Infof("ListHumanUsers: found %d human user(s) in %d result(s) at offset=%d", len(users), raw, offset)
	return users, raw, nil
}

// DeleteUser removes a Zitadel user.
// A gRPC NotFound error is swallowed and treated as success (idempotent).
func (c *SDKClient) DeleteUser(ctx context.Context, userID string) error {
	klog.V(2).Infof("DeleteUser: deleting user id=%q", userID)

	_, err := c.user.DeleteUser(ctx, &userv2.DeleteUserRequest{
		UserId: userID,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			klog.V(2).Infof("DeleteUser: user id=%q not found (idempotent)", userID)
			return nil
		}
		klog.Errorf("DeleteUser: failed to delete user id=%q: %v", userID, err)
		return fmt.Errorf("delete user: %w", err)
	}
	klog.V(2).Infof("DeleteUser: user id=%q deleted", userID)
	return nil
}

// DeactivateUser deactivates a Zitadel user within an organization.
// Returns nil if the user is not found (idempotent).
func (c *SDKClient) DeactivateUser(ctx context.Context, orgID, userID string) error {
	klog.V(2).Infof("DeactivateUser: deactivating user id=%q in org=%q", userID, orgID)

	// Set organization context in gRPC metadata
	ctxWithOrg := middleware.SetOrgID(ctx, orgID)

	_, err := c.user.DeactivateUser(ctxWithOrg, &userv2.DeactivateUserRequest{
		UserId: userID,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			klog.V(2).Infof("DeactivateUser: user id=%q not found (idempotent)", userID)
			return nil
		}
		klog.Errorf("DeactivateUser: failed to deactivate user id=%q: %v", userID, err)
		return fmt.Errorf("deactivate user: %w", err)
	}
	klog.V(2).Infof("DeactivateUser: user id=%q deactivated", userID)
	return nil
}

// ReactivateUser reactivates a Zitadel user within an organization.
// Returns nil if the user is not found (idempotent).
func (c *SDKClient) ReactivateUser(ctx context.Context, orgID, userID string) error {
	klog.V(2).Infof("ReactivateUser: reactivating user id=%q in org=%q", userID, orgID)

	// Set organization context in gRPC metadata
	ctxWithOrg := middleware.SetOrgID(ctx, orgID)

	_, err := c.user.ReactivateUser(ctxWithOrg, &userv2.ReactivateUserRequest{
		UserId: userID,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			klog.V(2).Infof("ReactivateUser: user id=%q not found (idempotent)", userID)
			return nil
		}
		klog.Errorf("ReactivateUser: failed to reactivate user id=%q: %v", userID, err)
		return fmt.Errorf("reactivate user: %w", err)
	}
	klog.V(2).Infof("ReactivateUser: user id=%q reactivated", userID)
	return nil
}

// ListMachineAccountsInOrganization lists all machine accounts (users) within an organization.
// Returns only users that are machine type.
func (c *SDKClient) ListMachineAccountsInOrganization(ctx context.Context, orgID string) ([]*User, error) {
	klog.V(2).Infof("ListMachineAccountsInOrganization: listing machine accounts in org=%q", orgID)

	// Set organization context in gRPC metadata
	ctxWithOrg := middleware.SetOrgID(ctx, orgID)

	resp, err := c.user.ListUsers(ctxWithOrg, &userv2.ListUsersRequest{
		Queries: []*userv2.SearchQuery{
			{Query: &userv2.SearchQuery_OrganizationIdQuery{
				OrganizationIdQuery: &userv2.OrganizationIdQuery{OrganizationId: orgID},
			}},
		},
	})
	if err != nil {
		klog.Errorf("ListMachineAccountsInOrganization: failed to list users: %v", err)
		return nil, fmt.Errorf("list users: %w", err)
	}

	machineAccounts := make([]*User, 0)
	for _, user := range resp.GetResult() {
		// Filter for machine users only
		if user.GetMachine() != nil {
			result := &User{
				ID:       user.GetUserId(),
				Username: localIdentityUsername(user),
				State:    user.GetState().String(),
			}
			machineAccounts = append(machineAccounts, result)
		}
	}

	klog.V(2).Infof("ListMachineAccountsInOrganization: found %d machine account(s) in org=%q", len(machineAccounts), orgID)
	return machineAccounts, nil
}

// ListMachineKeysInOrganization lists all machine keys for a user within an organization.
// Returns complete key information including ID, type, creation date, and expiration date.
func (c *SDKClient) ListMachineKeysInOrganization(ctx context.Context, orgID, userID string) ([]*MachineKey, error) {
	klog.V(2).Infof("ListMachineKeysInOrganization: listing keys for user id=%q in org=%q", userID, orgID)

	// Set organization context in gRPC metadata
	ctxWithOrg := middleware.SetOrgID(ctx, orgID)

	// List keys for the user filtered by organization and user ID
	resp, err := c.user.ListKeys(ctxWithOrg, &userv2.ListKeysRequest{
		Filters: []*userv2.KeysSearchFilter{
			{
				Filter: &userv2.KeysSearchFilter_OrganizationIdFilter{
					OrganizationIdFilter: &filterv2.IDFilter{Id: orgID},
				},
			},
			{
				Filter: &userv2.KeysSearchFilter_UserIdFilter{
					UserIdFilter: &filterv2.IDFilter{Id: userID},
				},
			},
		},
	})
	if err != nil {
		klog.Errorf("ListMachineKeysInOrganization: failed to list keys: %v", err)
		return nil, fmt.Errorf("list keys: %w", err)
	}

	keys := make([]*MachineKey, 0, len(resp.GetResult()))
	for _, key := range resp.GetResult() {
		mk := &MachineKey{
			ID:          key.GetId(),
			CreatedDate: key.GetCreationDate().AsTime(),
		}
		// ExpirationDate is optional
		if key.GetExpirationDate() != nil {
			expirationTime := key.GetExpirationDate().AsTime()
			mk.ExpirationDate = &expirationTime
		}
		keys = append(keys, mk)
	}

	klog.V(2).Infof("ListMachineKeysInOrganization: found %d keys for user id=%q in org=%q", len(keys), userID, orgID)
	return keys, nil
}

// RemoveMachineKeyInOrganization removes a machine key from a user within an organization.
// A gRPC NotFound error is swallowed and treated as success (idempotent).
func (c *SDKClient) RemoveMachineKeyInOrganization(ctx context.Context, orgID, userID, keyID string) error {
	klog.V(2).Infof("RemoveMachineKeyInOrganization: removing key id=%q from user id=%q in org=%q", keyID, userID, orgID)

	// Set organization context in gRPC metadata
	ctxWithOrg := middleware.SetOrgID(ctx, orgID)

	_, err := c.user.RemoveKey(ctxWithOrg, &userv2.RemoveKeyRequest{
		UserId: userID,
		KeyId:  keyID,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			klog.V(2).Infof("RemoveMachineKeyInOrganization: key id=%q not found (idempotent)", keyID)
			return nil
		}
		klog.Errorf("RemoveMachineKeyInOrganization: failed to remove key: %v", err)
		return fmt.Errorf("remove key: %w", err)
	}

	klog.V(2).Infof("RemoveMachineKeyInOrganization: key id=%q removed", keyID)
	return nil
}
