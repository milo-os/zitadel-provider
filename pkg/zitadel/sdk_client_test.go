package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	sessionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
)

// fakeUserService stubs the gRPC UserServiceClient. Only the methods under
// test are implemented; any other call panics via the embedded nil interface.
type fakeUserService struct {
	userv2.UserServiceClient
	listUsers    func(ctx context.Context, in *userv2.ListUsersRequest, opts ...grpc.CallOption) (*userv2.ListUsersResponse, error)
	listPasskeys func(ctx context.Context, in *userv2.ListPasskeysRequest, opts ...grpc.CallOption) (*userv2.ListPasskeysResponse, error)

	createPasskeyRegistrationLink func(ctx context.Context, in *userv2.CreatePasskeyRegistrationLinkRequest, opts ...grpc.CallOption) (*userv2.CreatePasskeyRegistrationLinkResponse, error)
	listAuthMethodTypes           func(ctx context.Context, in *userv2.ListAuthenticationMethodTypesRequest, opts ...grpc.CallOption) (*userv2.ListAuthenticationMethodTypesResponse, error)
}

func (f *fakeUserService) ListUsers(ctx context.Context, in *userv2.ListUsersRequest, opts ...grpc.CallOption) (*userv2.ListUsersResponse, error) {
	return f.listUsers(ctx, in, opts...)
}

func (f *fakeUserService) ListPasskeys(ctx context.Context, in *userv2.ListPasskeysRequest, opts ...grpc.CallOption) (*userv2.ListPasskeysResponse, error) {
	return f.listPasskeys(ctx, in, opts...)
}

func (f *fakeUserService) CreatePasskeyRegistrationLink(ctx context.Context, in *userv2.CreatePasskeyRegistrationLinkRequest, opts ...grpc.CallOption) (*userv2.CreatePasskeyRegistrationLinkResponse, error) {
	return f.createPasskeyRegistrationLink(ctx, in, opts...)
}

func (f *fakeUserService) ListAuthenticationMethodTypes(ctx context.Context, in *userv2.ListAuthenticationMethodTypesRequest, opts ...grpc.CallOption) (*userv2.ListAuthenticationMethodTypesResponse, error) {
	return f.listAuthMethodTypes(ctx, in, opts...)
}

func humanUser(id, username, email, given, family string, state userv2.UserState) *userv2.User {
	return &userv2.User{
		UserId:             id,
		Username:           username,
		PreferredLoginName: username,
		State:              state,
		Type: &userv2.User_Human{Human: &userv2.HumanUser{
			Profile: &userv2.HumanProfile{GivenName: given, FamilyName: family},
			Email:   &userv2.HumanEmail{Email: email},
		}},
	}
}

func TestListHumanUsers(t *testing.T) {
	t.Run("maps human users and requests server-side human filter", func(t *testing.T) {
		// Arrange
		var gotReq *userv2.ListUsersRequest
		c := &SDKClient{user: &fakeUserService{
			listUsers: func(_ context.Context, in *userv2.ListUsersRequest, _ ...grpc.CallOption) (*userv2.ListUsersResponse, error) {
				gotReq = in
				return &userv2.ListUsersResponse{Result: []*userv2.User{
					humanUser("u1", "alice", "alice@example.com", "Alice", "Doe", userv2.UserState_USER_STATE_ACTIVE),
					humanUser("u2", "bob", "bob@example.com", "Bob", "Roe", userv2.UserState_USER_STATE_INACTIVE),
				}}, nil
			},
		}}

		// Act
		users, raw, err := c.ListHumanUsers(context.Background(), 40, 20)

		// Assert
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(users) != 2 {
			t.Fatalf("expected 2 users, got %d", len(users))
		}
		if raw != 2 {
			t.Fatalf("expected raw page count 2, got %d", raw)
		}
		want := User{ID: "u1", Username: "alice", Email: "alice@example.com", State: "USER_STATE_ACTIVE", GivenName: "Alice", FamilyName: "Doe"}
		if users[0] != want {
			t.Errorf("user[0] = %+v, want %+v", users[0], want)
		}
		if users[1].State != "USER_STATE_INACTIVE" {
			t.Errorf("user[1].State = %q, want USER_STATE_INACTIVE (state must not filter results)", users[1].State)
		}

		if gotReq.GetQuery().GetOffset() != 40 || gotReq.GetQuery().GetLimit() != 20 || !gotReq.GetQuery().GetAsc() {
			t.Errorf("pagination query = %+v, want offset=40 limit=20 asc=true", gotReq.GetQuery())
		}
		if len(gotReq.GetQueries()) != 1 {
			t.Fatalf("expected exactly 1 search query (type filter), got %d", len(gotReq.GetQueries()))
		}
		tq := gotReq.GetQueries()[0].GetTypeQuery()
		if tq == nil || tq.GetType() != userv2.Type_TYPE_HUMAN {
			t.Errorf("search query = %+v, want TypeQuery TYPE_HUMAN", gotReq.GetQueries()[0])
		}
	})

	t.Run("defensively skips non-human results", func(t *testing.T) {
		// Arrange
		c := &SDKClient{user: &fakeUserService{
			listUsers: func(_ context.Context, _ *userv2.ListUsersRequest, _ ...grpc.CallOption) (*userv2.ListUsersResponse, error) {
				return &userv2.ListUsersResponse{Result: []*userv2.User{
					{UserId: "m1", Username: "robot", State: userv2.UserState_USER_STATE_ACTIVE,
						Type: &userv2.User_Machine{Machine: &userv2.MachineUser{}}},
					humanUser("u1", "alice", "alice@example.com", "Alice", "Doe", userv2.UserState_USER_STATE_ACTIVE),
				}}, nil
			},
		}}

		// Act
		users, raw, err := c.ListHumanUsers(context.Background(), 0, 10)

		// Assert
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(users) != 1 || users[0].ID != "u1" {
			t.Fatalf("expected only the human user u1, got %+v", users)
		}
		if raw != 2 {
			t.Fatalf("raw must count the full server page including skipped rows: want 2, got %d", raw)
		}
	})

	t.Run("propagates API errors", func(t *testing.T) {
		// Arrange
		boom := errors.New("boom")
		c := &SDKClient{user: &fakeUserService{
			listUsers: func(_ context.Context, _ *userv2.ListUsersRequest, _ ...grpc.CallOption) (*userv2.ListUsersResponse, error) {
				return nil, boom
			},
		}}

		// Act
		_, _, err := c.ListHumanUsers(context.Background(), 0, 10)

		// Assert
		if !errors.Is(err, boom) {
			t.Fatalf("expected wrapped boom error, got %v", err)
		}
	})
}

func TestListPasskeys(t *testing.T) {
	t.Run("maps passkeys with raw AuthFactorState strings", func(t *testing.T) {
		// Arrange
		var gotReq *userv2.ListPasskeysRequest
		c := &SDKClient{user: &fakeUserService{
			listPasskeys: func(_ context.Context, in *userv2.ListPasskeysRequest, _ ...grpc.CallOption) (*userv2.ListPasskeysResponse, error) {
				gotReq = in
				return &userv2.ListPasskeysResponse{Result: []*userv2.Passkey{
					{Id: "pk-1", Name: "MacBook Touch ID", State: userv2.AuthFactorState_AUTH_FACTOR_STATE_READY},
					{Id: "pk-2", Name: "Old YubiKey", State: userv2.AuthFactorState_AUTH_FACTOR_STATE_NOT_READY},
				}}, nil
			},
		}}

		// Act
		passkeys, err := c.ListPasskeys(context.Background(), "user-1")

		// Assert
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []Passkey{
			{ID: "pk-1", Name: "MacBook Touch ID", State: "AUTH_FACTOR_STATE_READY"},
			{ID: "pk-2", Name: "Old YubiKey", State: "AUTH_FACTOR_STATE_NOT_READY"},
		}
		if len(passkeys) != len(want) || passkeys[0] != want[0] || passkeys[1] != want[1] {
			t.Errorf("ListPasskeys() = %+v, want %+v", passkeys, want)
		}
		if gotReq.GetUserId() != "user-1" {
			t.Errorf("request UserId = %q, want %q", gotReq.GetUserId(), "user-1")
		}
	})

	t.Run("empty result returns empty slice, not nil", func(t *testing.T) {
		c := &SDKClient{user: &fakeUserService{
			listPasskeys: func(context.Context, *userv2.ListPasskeysRequest, ...grpc.CallOption) (*userv2.ListPasskeysResponse, error) {
				return &userv2.ListPasskeysResponse{}, nil
			},
		}}
		passkeys, err := c.ListPasskeys(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if passkeys == nil || len(passkeys) != 0 {
			t.Errorf("ListPasskeys() = %#v, want empty non-nil slice", passkeys)
		}
	})

	t.Run("propagates API errors", func(t *testing.T) {
		boom := errors.New("boom")
		c := &SDKClient{user: &fakeUserService{
			listPasskeys: func(context.Context, *userv2.ListPasskeysRequest, ...grpc.CallOption) (*userv2.ListPasskeysResponse, error) {
				return nil, boom
			},
		}}
		_, err := c.ListPasskeys(context.Background(), "user-1")
		if !errors.Is(err, boom) {
			t.Fatalf("expected wrapped boom error, got %v", err)
		}
	})
}

func TestMapZitadelSessionPasskeyVerified(t *testing.T) {
	c := &SDKClient{}
	tests := []struct {
		name    string
		factors *sessionv2.Factors
		want    bool
	}{
		{"nil factors", nil, false},
		{"no webAuthN factor", &sessionv2.Factors{}, false},
		{"webAuthN present but not user-verified", &sessionv2.Factors{WebAuthN: &sessionv2.WebAuthNFactor{UserVerified: false}}, false},
		{"webAuthN user-verified (passkey)", &sessionv2.Factors{WebAuthN: &sessionv2.WebAuthNFactor{UserVerified: true}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := c.mapZitadelSession(&sessionv2.Session{Factors: tt.factors})
			if s.PasskeyVerified != tt.want {
				t.Errorf("PasskeyVerified = %v, want %v", s.PasskeyVerified, tt.want)
			}
		})
	}
}

// A-PR1. Zitadel transports metadata values as bytes; the domain type exposes a
// decoded string, because every caller so far wants to json.Unmarshal it — the
// passkey:<tokenID>:created convention auth-ui writes at enrollment.
func TestUserMetadata_DecodesValueForJSONUnmarshal(t *testing.T) {
	m := UserMetadata{Key: "passkey:abc123:created", Value: `{"name":"iCloud Keychain"}`}

	var payload struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(m.Value), &payload); err != nil {
		t.Fatalf("value must be JSON-decodable without further decoding: %v", err)
	}
	if payload.Name != "iCloud Keychain" {
		t.Fatalf("got %q, want %q", payload.Name, "iCloud Keychain")
	}
}

// Legacy entries hold a bare ISO date rather than JSON. The type must carry
// them without loss; it is the caller's job to fail the unmarshal and omit the
// passkey name (the passkey-removed design's fifth degradation path).
func TestUserMetadata_CarriesLegacyBareValue(t *testing.T) {
	m := UserMetadata{Key: "passkey:legacy:created", Value: "2026-01-02T15:04:05Z"}

	var payload struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(m.Value), &payload); err == nil {
		t.Fatal("a bare ISO value must fail JSON unmarshal, so the caller omits the name")
	}
	if m.Value != "2026-01-02T15:04:05Z" {
		t.Fatalf("value must round-trip unmodified, got %q", m.Value)
	}
}

func TestCreatePasskeyRegistrationLink(t *testing.T) {
	t.Run("asks for the ReturnCode medium and returns the code pair", func(t *testing.T) {
		// Arrange
		var gotReq *userv2.CreatePasskeyRegistrationLinkRequest
		c := &SDKClient{user: &fakeUserService{
			createPasskeyRegistrationLink: func(_ context.Context, in *userv2.CreatePasskeyRegistrationLinkRequest, _ ...grpc.CallOption) (*userv2.CreatePasskeyRegistrationLinkResponse, error) {
				gotReq = in
				return &userv2.CreatePasskeyRegistrationLinkResponse{
					Code: &userv2.PasskeyRegistrationCode{Id: "code-id-1", Code: "K7QM2XD4"},
				}, nil
			},
		}}

		// Act
		codeID, code, err := c.CreatePasskeyRegistrationLink(context.Background(), "user-1")

		// Assert
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if codeID != "code-id-1" || code != "K7QM2XD4" {
			t.Errorf("CreatePasskeyRegistrationLink() = (%q, %q), want (%q, %q)", codeID, code, "code-id-1", "K7QM2XD4")
		}
		if gotReq.GetUserId() != "user-1" {
			t.Errorf("request UserId = %q, want %q", gotReq.GetUserId(), "user-1")
		}
		// The ReturnCode medium is what keeps the code out of Zitadel's SMTP: it
		// comes back to us and leaves through the Datum mail pipeline instead.
		if gotReq.GetReturnCode() == nil {
			t.Errorf("request medium = %#v, want the ReturnCode oneof", gotReq.GetMedium())
		}
		if gotReq.GetSendLink() != nil {
			t.Error("request set the SendLink medium; Zitadel SMTP must stay dark")
		}
	})

	t.Run("rejects a response with no code", func(t *testing.T) {
		c := &SDKClient{user: &fakeUserService{
			createPasskeyRegistrationLink: func(context.Context, *userv2.CreatePasskeyRegistrationLinkRequest, ...grpc.CallOption) (*userv2.CreatePasskeyRegistrationLinkResponse, error) {
				return &userv2.CreatePasskeyRegistrationLinkResponse{}, nil
			},
		}}
		if _, _, err := c.CreatePasskeyRegistrationLink(context.Background(), "user-1"); err == nil {
			t.Fatal("expected an error for an empty code, got nil")
		}
	})

	t.Run("propagates API errors", func(t *testing.T) {
		boom := errors.New("boom")
		c := &SDKClient{user: &fakeUserService{
			createPasskeyRegistrationLink: func(context.Context, *userv2.CreatePasskeyRegistrationLinkRequest, ...grpc.CallOption) (*userv2.CreatePasskeyRegistrationLinkResponse, error) {
				return nil, boom
			},
		}}
		_, _, err := c.CreatePasskeyRegistrationLink(context.Background(), "user-1")
		if !errors.Is(err, boom) {
			t.Fatalf("expected wrapped boom error, got %v", err)
		}
	})
}

func TestListAuthMethodTypes(t *testing.T) {
	t.Run("maps the enum to its raw names", func(t *testing.T) {
		// Arrange
		var gotReq *userv2.ListAuthenticationMethodTypesRequest
		c := &SDKClient{user: &fakeUserService{
			listAuthMethodTypes: func(_ context.Context, in *userv2.ListAuthenticationMethodTypesRequest, _ ...grpc.CallOption) (*userv2.ListAuthenticationMethodTypesResponse, error) {
				gotReq = in
				return &userv2.ListAuthenticationMethodTypesResponse{
					AuthMethodTypes: []userv2.AuthenticationMethodType{
						userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSKEY,
					},
				}, nil
			},
		}}

		// Act
		types, err := c.ListAuthMethodTypes(context.Background(), "user-1")

		// Assert
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"AUTHENTICATION_METHOD_TYPE_PASSKEY"}
		if len(types) != len(want) || types[0] != want[0] {
			t.Errorf("ListAuthMethodTypes() = %+v, want %+v", types, want)
		}
		if gotReq.GetUserId() != "user-1" {
			t.Errorf("request UserId = %q, want %q", gotReq.GetUserId(), "user-1")
		}
	})

	t.Run("empty result returns empty slice, not nil", func(t *testing.T) {
		c := &SDKClient{user: &fakeUserService{
			listAuthMethodTypes: func(context.Context, *userv2.ListAuthenticationMethodTypesRequest, ...grpc.CallOption) (*userv2.ListAuthenticationMethodTypesResponse, error) {
				return &userv2.ListAuthenticationMethodTypesResponse{}, nil
			},
		}}
		types, err := c.ListAuthMethodTypes(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if types == nil || len(types) != 0 {
			t.Errorf("ListAuthMethodTypes() = %#v, want empty non-nil slice", types)
		}
	})

	t.Run("propagates API errors", func(t *testing.T) {
		boom := errors.New("boom")
		c := &SDKClient{user: &fakeUserService{
			listAuthMethodTypes: func(context.Context, *userv2.ListAuthenticationMethodTypesRequest, ...grpc.CallOption) (*userv2.ListAuthenticationMethodTypesResponse, error) {
				return nil, boom
			},
		}}
		_, err := c.ListAuthMethodTypes(context.Background(), "user-1")
		if !errors.Is(err, boom) {
			t.Fatalf("expected wrapped boom error, got %v", err)
		}
	})
}
