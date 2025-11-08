package iam

import "time"

// User represents a user in the system
type User struct {
	Id           string    `json:"id"`
	Username     string    `json:"username"`
	Password     string    `json:"password,omitempty"`
	PasswordHash string    `json:"password_hash,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Token represents authentication token
type Token struct {
	Id        string    `json:"id"`
	UserId    string    `json:"user_id"`
	IsRevoked bool      `json:"is_revoked"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
