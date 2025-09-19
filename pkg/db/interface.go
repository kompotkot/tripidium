package db

import (
	"context"

	"github.com/kompotkot/tripidium/pkg/iam"
)

// Database represents a common interface for database operations
type Database interface {
	// TestConnection tests the database connection with a timeout
	TestConnection(ctx context.Context) error

	// Close closes the database connection
	Close() error

	// GetUser retrieves a user from the database
	GetUser(ctx context.Context, userId, email string) (iam.User, error)

	// GetToken retrieves a token from the database
	GetToken(ctx context.Context, tokenId string) (iam.Token, error)
}
