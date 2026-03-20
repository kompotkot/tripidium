package server

import (
	"time"

	"github.com/kompotkot/tripidium/pkg/iam"
)

// UserResponse is the HTTP JSON body for user endpoints
type UserResponse struct {
	Id        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Phone     *int      `json:"phone,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ToUserResponse maps iam.User to UserResponse
func ToUserResponse(u iam.User) UserResponse {
	user := UserResponse{
		Id:        u.ID.String(),
		Username:  u.Username,
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
	if u.Phone != 0 {
		user.Phone = &u.Phone
	}
	return user
}

// AuthLoginResponse is the HTTP JSON body for login endpoint
type AuthLoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// ToAuthLoginResponse maps to AuthLoginResponse
func ToAuthLoginResponse(accessToken, refreshToken string) AuthLoginResponse {
	return AuthLoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
}
