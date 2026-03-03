package db

import (
	"context"

	"github.com/kompotkot/tripidium/pkg/iam"

	"github.com/google/uuid"
)

// Database represents a common interface for database operations aligned with API endpoints
type Database interface {
	// --- Service ---
	// TestConnection tests the database connection with a timeout
	TestConnection(ctx context.Context) error

	// Close closes the database connection
	Close() error

	// --- Users ---

	// CreateUser creates a new user
	CreateUser(ctx context.Context, username, email, passwordHash string) (iam.User, error)
	// GetUser returns the user by ID or Username
	GetUser(ctx context.Context, userID, username string) (iam.User, error)
	// UpdateUser updates profile fields
	UpdateUser(ctx context.Context, userID uuid.UUID, username, email, phone string) (iam.User, error)
	// UpdateUserPassword sets a new password hash (PUT /user/password)
	UpdateUserPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error

	// --- Auth sessions ---

	// CreateAuthSession creates a session after login
	CreateAuthSession(ctx context.Context, userID uuid.UUID, refreshTokenHash, clientIP, userAgent string) (iam.AuthSession, error)
	// GetAuthSession returns a session by ID
	GetAuthSession(ctx context.Context, sessionID uuid.UUID) (iam.AuthSession, error)
	// GetAuthSessionByRefreshToken returns a session by refresh token hash
	GetAuthSessionByRefreshToken(ctx context.Context, refreshTokenHash string) (iam.AuthSession, error)
	// ListAuthSessions returns all sessions for a user
	ListAuthSessions(ctx context.Context, userID uuid.UUID) ([]iam.AuthSession, error)
	// RevokeAuthSession revokes one session, optionally marking it replaced by another
	RevokeAuthSession(ctx context.Context, sessionID uuid.UUID, reason string, replacedBy *uuid.UUID) error
	// RevokeAllAuthSessions revokes every session for a user
	RevokeAllAuthSessions(ctx context.Context, userID uuid.UUID) error
}
