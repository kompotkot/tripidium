package db

import (
	"context"
	"time"

	"github.com/kompotkot/tripidium/pkg/model"

	"github.com/google/uuid"
)

// Database represents a common interface for database operations aligned with API endpoints
type Database interface {
	// --- Service ---
	// TestConnection tests the database connection with a timeout
	TestConnection(ctx context.Context) error

	// Close closes the database connection
	Close() error

	// --- Subjects ---

	// GetSubject returns a subject by ID
	GetSubject(ctx context.Context, subjectID uuid.UUID) (model.Subject, error)

	// --- Users ---

	// CreateUser creates a new user
	CreateUser(ctx context.Context, userID uuid.UUID, isActive bool, username, email, passwordHash string, phone int) (model.User, error)
	// GetUser returns the user by ID, username, or email.
	GetUser(ctx context.Context, userID, username, email string) (model.User, error)
	// UpdateUser updates profile fields
	UpdateUser(ctx context.Context, userID uuid.UUID, username, email, phone string) (model.User, error)
	// UpdateUserPassword sets a new password hash (PUT /identity/users/current/password)
	UpdateUserPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error

	// CheckUserInvite verifies invite code is valid and unclaimed
	CheckUserInvite(ctx context.Context, inviteCode string) (bool, error)
	// ClaimUserInvite atomically verifies invite code and marks it as used
	ClaimUserInvite(ctx context.Context, inviteCode string, userID uuid.UUID) error

	// --- Auth sessions ---

	// CreateAuthSession creates a session after login
	CreateAuthSession(ctx context.Context, sessionID uuid.UUID, subjectID, familyID uuid.UUID, refreshTokenHash, createdIP string, createdUserAgent *string, expiresAt time.Time) (model.AuthSession, error)
	// GetAuthSession returns a session by ID
	GetAuthSession(ctx context.Context, sessionID uuid.UUID) (model.AuthSession, error)
	// GetAuthSessionByRefreshToken returns a session by refresh token hash
	GetAuthSessionByRefreshToken(ctx context.Context, refreshTokenHash string) (model.AuthSession, error)
	// RefreshAuthSession atomically rotates a refresh-token session and returns new session
	RefreshAuthSession(ctx context.Context, oldRefreshTokenHash string, newSessionID uuid.UUID, newRefreshTokenHash, createdIP string, createdUserAgent *string, expiresAt time.Time) (model.AuthSession, error)
	// ListAuthSessions returns all active sessions for a subject
	ListAuthSessions(ctx context.Context, subjectID uuid.UUID) ([]model.AuthSession, error)
	// RevokeAuthSession revokes one session, optionally marking it replaced by another
	RevokeAuthSession(ctx context.Context, sessionID, subjectID uuid.UUID, reason string, replacedBy *uuid.UUID) error
	// RevokeAllAuthSessions revokes every active session for a subject
	RevokeAllAuthSessions(ctx context.Context, subjectID uuid.UUID) error

	// --- Organizations ---

	// CreateOrganization creates an organization subject, its profile, and assigns ownerUserID as owner
	CreateOrganization(ctx context.Context, orgID uuid.UUID, name string, description *string, ownerUserID uuid.UUID) (model.Organization, error)
	// GetOrganization returns an organization by ID
	GetOrganization(ctx context.Context, orgID uuid.UUID) (model.Organization, error)
	// ListOrganizations returns organizations where the given user is a member
	ListOrganizations(ctx context.Context, userID uuid.UUID) ([]model.Organization, error)
	// UpdateOrganization updates editable organization fields; nil pointer means keep current value
	UpdateOrganization(ctx context.Context, orgID uuid.UUID, name *string, description *string) (model.Organization, error)
	// DeleteOrganization deletes an organization subject and cascades to its profile and members
	DeleteOrganization(ctx context.Context, orgID uuid.UUID) error

	// --- Organization members ---

	// ListOrganizationMembers returns all membership records for an organization
	ListOrganizationMembers(ctx context.Context, orgID uuid.UUID) ([]model.OrganizationMember, error)
	// AddOrganizationMember adds a user to an organization with the given role
	AddOrganizationMember(ctx context.Context, orgID uuid.UUID, userID uuid.UUID, role string) (model.OrganizationMember, error)
	// GetOrganizationMember returns membership details for a specific user in an organization
	GetOrganizationMember(ctx context.Context, orgID uuid.UUID, userID uuid.UUID) (model.OrganizationMember, error)
	// UpdateOrganizationMemberRole updates the role for a specific user in an organization
	UpdateOrganizationMemberRole(ctx context.Context, orgID uuid.UUID, userID uuid.UUID, role string) (model.OrganizationMember, error)
	// RemoveOrganizationMember removes a user from an organization
	RemoveOrganizationMember(ctx context.Context, orgID uuid.UUID, userID uuid.UUID) error
}
