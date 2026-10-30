package zitadel

import (
	"context"
	"fmt"
	"net/http"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// UserResponse represents the response from the GET /v2/users/:userId endpoint.
type GetUserResponse struct {
	Details UserDetails `json:"details"`
	User    User        `json:"user"`
}

// UserState represents the state of a user returned by Zitadel’s API.
type UserState string

const (
	UserStateActive   UserState = "USER_STATE_ACTIVE"
	UserStateInactive UserState = "USER_STATE_INACTIVE"
)

// UserDetails contains metadata about the user resource.
type UserDetails struct {
	Sequence      string `json:"sequence"`
	ChangeDate    string `json:"changeDate"`
	ResourceOwner string `json:"resourceOwner"`
	CreationDate  string `json:"creationDate"`
}

// User represents the user object within the UserResponse.
type User struct {
	UserID             string           `json:"userId"`
	Details            UserDetails      `json:"details"`
	State              UserState        `json:"state"`
	Username           string           `json:"username"`
	LoginNames         []string         `json:"loginNames"`
	PreferredLoginName string           `json:"preferredLoginName"`
	Machine            *MachineUserData `json:"machine,omitempty"`
	Human              *HumanUserData   `json:"human,omitempty"`
}

// MachineUserData represents machine-specific user data.
// This can be extended with machine-specific fields as needed.
type MachineUserData struct{}

// HumanUserData represents human-specific user data.
// This can be extended with human-specific fields as needed.
type HumanUserData struct{}

// GetUser retrieves user information by user ID.
// It wraps the "GET /v2/users/:userId" REST endpoint.
// See https://zitadel.com/docs/apis/resources/user_service_v2/user-service-get-user-by-id for authoritative docs.
func (c *Client) GetUser(ctx context.Context, userID string) (*GetUserResponse, error) {
	log := logf.FromContext(ctx).WithName("zitadel-client")
	log.Info("Getting user information", "userID", userID)

	var resp GetUserResponse
	path := fmt.Sprintf("v2/users/%s", userID)
	if err := c.do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, apierrors.NewNotFound(schema.GroupResource{Group: "zitadel", Resource: "users"}, userID)
		}
		log.Error(err, "Failed to get user information", "userID", userID)
		return nil, err
	}

	log.Info("Successfully retrieved user information", "userID", userID, "username", resp.User.Username)
	return &resp, nil
}
