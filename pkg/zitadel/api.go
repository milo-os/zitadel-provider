package zitadel

import (
	"context"
	"time"
)

// OrgIDForProject returns the Zitadel organization ID for a given project name.
// The "project-" prefix ensures the controller's org does not collide with
// infrastructure-managed organizations that use the bare project name.
func OrgIDForProject(projectName string) string {
	return "project-" + projectName
}

// OrgDisplayNameForProject returns the display name used when creating a
// Zitadel organization for a project. The "Project - " prefix keeps the
// display name unique from the bare project name that Zitadel already
// reserves as a domain label on the old (un-prefixed) organization.
func OrgDisplayNameForProject(projectName string) string {
	return "Project - " + projectName
}

// Session represents a Zitadel session distilled for Kubernetes exposure.
type Session struct {
	ID            string
	UserID        string
	IP            string
	FingerprintID string
	CreatedAt     time.Time
	LastUpdated   *time.Time
	UserAgent     string
	// Metadata is the arbitrary key/value bag Zitadel exposes on a session.
	// Today it carries the MaxMind device-tracking token (key
	// "maxmind/tracking-token"); the apiserver mirrors selected entries onto
	// the milo Session as annotations so they can be read by downstream
	// consumers like the fraud service.
	Metadata map[string]string
	// PasskeyVerified is true when this session's most recent authentication
	// included a user-verified WebAuthN factor (Factors.WebAuthN.UserVerified) —
	// the closest available signal that the login was a passkey/passwordless
	// ceremony rather than password+OTP. Used to exempt passkey logins from
	// the suspicious-login notification (see internal/httpactionsserver).
	PasskeyVerified bool
}

// IDPLink represents an identity provider link for a user.
type IDPLink struct {
	IDPID       string
	IDPName     string
	UserID      string
	IDPUserName string
}

// Passkey represents a Zitadel WebAuthn passkey credential for a user.
// UserMetadata is one key/value entry from a Zitadel user's metadata bag.
//
// Value is the DECODED string. Zitadel transports it as bytes, and every caller
// so far wants to json.Unmarshal it — the passkey:<tokenID>:created convention
// auth-ui writes at enrollment, whose value is JSON with a .name field. Legacy
// entries hold a bare RFC 3339 date instead; this type carries those unchanged
// and leaves it to the caller to fail the unmarshal and degrade.
type UserMetadata struct {
	Key          string
	Value        string
	CreationDate time.Time
}

type Passkey struct {
	ID   string
	Name string
	// State is the raw Zitadel AuthFactorState string (e.g.
	// "AUTH_FACTOR_STATE_READY"). Callers map it to a domain-level
	// Active/Inactive status; this package stays a thin, faithful mirror
	// of the Zitadel wire shape (see User.State for the same convention).
	State string
}

// User represents a Zitadel user with minimal fields.
type User struct {
	ID       string
	Username string
	Email    string
	State    string // e.g. "ACTIVE", "INACTIVE"
	// GivenName and FamilyName carry the human profile; empty for machine users.
	GivenName  string
	FamilyName string
	// IsEmailVerified reports whether the user has proven ownership of Email.
	// It is the authoritative source for milo's User.status.emailVerified and
	// the signal abandoned-account GC selects on.
	IsEmailVerified bool
	// CreatedAt is when the Zitadel account was created. GC compares it against
	// the retention window; the zero value means the API did not report one, and
	// callers must treat that as "unknown age" rather than "ancient".
	CreatedAt time.Time
}

// Organization represents a Zitadel organization.
type Organization struct {
	ID   string
	Name string
}

// MachineKey represents a machine account key with complete information.
type MachineKey struct {
	ID             string     // Key ID
	CreatedDate    time.Time  // When the key was created
	ExpirationDate *time.Time // When the key expires (nil if no expiration)
}

// API is the minimal surface needed by our storage and controllers.
type API interface {
	// session management
	ListSessions(ctx context.Context, userID string) ([]Session, error)
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, userID, sessionID string) error
	ListIDPLinks(ctx context.Context, userID string) ([]IDPLink, error)

	// passkey management
	ListPasskeys(ctx context.Context, userID string) ([]Passkey, error)

	// passkey registration (Phase C recovery)
	CreatePasskeyRegistrationLink(ctx context.Context, userID string) (codeID, code string, err error)
	// ListAuthMethodTypes returns Zitadel's AuthenticationMethodType names for the user,
	// e.g. AUTHENTICATION_METHOD_TYPE_PASSKEY. Used by the C9 gauge.
	ListAuthMethodTypes(ctx context.Context, userID string) ([]string, error)

	// organization management
	CreateOrganization(ctx context.Context, name string) (orgID string, err error)
	CreateOrganizationWithID(ctx context.Context, name, customOrgID string) (orgID string, err error)
	DeleteOrganization(ctx context.Context, orgID string) error
	GetOrganization(ctx context.Context, orgID string) (*Organization, error)

	// user management
	GetUserByID(ctx context.Context, userID string) (*User, error)
	ListHumanUsers(ctx context.Context, offset uint64, limit uint32) ([]User, int, error)
	GetMachineUserByUsername(ctx context.Context, orgID, username string) (*User, error)
	AddMachineUserInOrganization(ctx context.Context, orgID, userID, username, displayName string) (createdUserID string, err error)
	DeleteUser(ctx context.Context, userID string) error
	ListUserMetadata(ctx context.Context, userID string) ([]UserMetadata, error)
	DeactivateUser(ctx context.Context, orgID, userID string) error
	ReactivateUser(ctx context.Context, orgID, userID string) error

	// machine accounts and keys in organization
	ListMachineAccountsInOrganization(ctx context.Context, orgID string) ([]*User, error)
	AddMachineKeyInOrganization(ctx context.Context, orgID, userID string, publicKey []byte, expirationDate *time.Time) (keyID string, keyContent []byte, err error)
	ListMachineKeysInOrganization(ctx context.Context, orgID, userID string) ([]*MachineKey, error)
	RemoveMachineKeyInOrganization(ctx context.Context, orgID, userID, keyID string) error
}
