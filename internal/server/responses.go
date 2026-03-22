package server

import (
	"encoding/hex"
	"net"
	"strings"
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
	AccessToken string `json:"access_token"`
}

// ToAuthLoginResponse maps to AuthLoginResponse
func ToAuthLoginResponse(accessToken, refreshToken string) AuthLoginResponse {
	return AuthLoginResponse{
		AccessToken: accessToken,
	}
}

// AuthSessionResponse is the safe HTTP JSON body for session list endpoint
type AuthSessionResponse struct {
	Id        string    `json:"id"`
	IsCurrent bool      `json:"is_current"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UserAgent string    `json:"user_agent"`
	IP        string    `json:"ip"`
}

// ToAuthSessionResponse maps iam.AuthSession to a safe response DTO
func ToAuthSessionResponse(s iam.AuthSession, currentSessionID string) AuthSessionResponse {
	userAgent := ""
	if s.CreatedUserAgent != nil {
		userAgent = strings.TrimSpace(*s.CreatedUserAgent)
	}

	return AuthSessionResponse{
		Id:        s.ID.String(),
		IsCurrent: s.ID.String() == currentSessionID,
		CreatedAt: s.CreatedAt,
		ExpiresAt: s.ExpiresAt,
		UserAgent: userAgent,
		IP:        normalizeSessionIP(s.CreatedIP.String()),
	}
}

// ToAuthSessionsResponse maps list of auth sessions to safe response DTOs
func ToAuthSessionsResponse(sessions []iam.AuthSession, currentSessionID string) []AuthSessionResponse {
	out := make([]AuthSessionResponse, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, ToAuthSessionResponse(s, currentSessionID))
	}
	return out
}

func normalizeSessionIP(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" || value == "<nil>" {
		return ""
	}

	// Some DB driver paths may expose byte-backed IP values as "?<hex>" or "\\x<hex>"
	hexPayload := ""
	switch {
	case strings.HasPrefix(value, "?"):
		hexPayload = value[1:]
	case strings.HasPrefix(value, "\\x"):
		hexPayload = value[2:]
	}
	if hexPayload != "" {
		if decoded, err := hex.DecodeString(hexPayload); err == nil {
			value = strings.TrimSpace(string(decoded))
		}
	}

	if parsed := net.ParseIP(value); parsed != nil {
		return parsed.String()
	}
	return value
}
