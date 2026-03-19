package iam

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID           uuid.UUID // id
	IsActive     bool      // is_active
	Username     string    // username
	Email        string    // email
	Phone        int       // phone, nullable
	PasswordHash string    // password_hash
	CreatedAt    time.Time // created_at
	UpdatedAt    time.Time // updated_at
}

// AuthSession represents authentication session
type AuthSession struct {
	ID               uuid.UUID  // id
	UserID           uuid.UUID  // user_id
	RefreshTokenHash string     // refresh_token_hash
	CreatedIP        net.IP     // created_ip
	CreatedUserAgent *string    // created_user_agent, nullable
	RevokeReason     *string    // revoke_reason, nullable
	RevokedAt        *time.Time // revoked_at, nullable
	CreatedAt        time.Time  // created_at
	ExpiresAt        time.Time  // expires_at
	ReplacedBy       *uuid.UUID // replaced_by, nullable
}
