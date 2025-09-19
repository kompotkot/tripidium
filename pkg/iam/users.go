package iam

import "time"

// User represents a user in the system
type User struct {
	Id           string    `json:"id"`
	Email        string    `json:"email"`
	Password     string    `json:"password,omitempty"`
	PasswordHash string    `json:"password_hash,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Token represents authentication Bearer token
type Token struct {
	Id        string    `json:"id"`
	UserId    string    `json:"user_id"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
