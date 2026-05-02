package dto

import "time"

type AuthSignUpRequest struct {
	Username   string  `json:"username"`
	Email      string  `json:"email"`
	Password   string  `json:"password"`
	Phone      *int    `json:"phone,omitempty"`
	InviteCode *string `json:"invite_code,omitempty"`
}

type AuthLoginRequest struct {
	Username *string `json:"username,omitempty"`
	Email    *string `json:"email,omitempty"`
	Password string  `json:"password"`
}

type AuthLoginResponse struct {
	AccessToken string `json:"access_token"`
}

type AuthSessionResponse struct {
	Id        string    `json:"id"`
	IsCurrent bool      `json:"is_current"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UserAgent string    `json:"user_agent"`
	IP        string    `json:"ip"`
}
