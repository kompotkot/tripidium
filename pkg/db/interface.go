package db

import (
	"context"
	"time"

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
	CreateUser(ctx context.Context, userID uuid.UUID, isActive bool, username, email, passwordHash string, phone int) (iam.User, error)
	// GetUser returns the user by ID or Username
	GetUser(ctx context.Context, userID, username, email string) (iam.User, error)
	// UpdateUser updates profile fields
	UpdateUser(ctx context.Context, userID uuid.UUID, username, email, phone string) (iam.User, error)
	// UpdateUserPassword sets a new password hash (PUT /user/password)
	UpdateUserPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error

	// --- Auth sessions ---

	// CreateAuthSession creates a session after login
	CreateAuthSession(ctx context.Context, sessionID uuid.UUID, userID, familyID uuid.UUID, refreshTokenHash, createdIP string, createdUserAgent *string, expiresAt time.Time) (iam.AuthSession, error)
	// GetAuthSession returns a session by ID
	GetAuthSession(ctx context.Context, sessionID uuid.UUID) (iam.AuthSession, error)
	// GetAuthSessionByRefreshToken returns a session by refresh token hash
	GetAuthSessionByRefreshToken(ctx context.Context, refreshTokenHash string) (iam.AuthSession, error)
	// RefreshAuthSession atomically rotates a refresh-token session and returns new session
	RefreshAuthSession(ctx context.Context, oldRefreshTokenHash string, newSessionID uuid.UUID, newRefreshTokenHash, createdIP string, createdUserAgent *string, expiresAt time.Time) (iam.AuthSession, error)
	// ListAuthSessions returns all sessions for a user
	ListAuthSessions(ctx context.Context, userID uuid.UUID) ([]iam.AuthSession, error)
	// RevokeAuthSession revokes one session, optionally marking it replaced by another
	RevokeAuthSession(ctx context.Context, sessionID uuid.UUID, reason string, replacedBy *uuid.UUID) error
	// RevokeAllAuthSessions revokes every session for a user
	RevokeAllAuthSessions(ctx context.Context, userID uuid.UUID) error
}
