package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/kompotkot/tripidium/pkg/db"
	"github.com/kompotkot/tripidium/pkg/iam"

	"golang.org/x/crypto/argon2"
)

// TODO(kompotkot): Move to configuration
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	saltLen      int    = 16
)

// hashPassword securely hashes a password using Argon2 algorithm
func hashPassword(password string) (string, error) {
	// Generate a random salt for password hashing
	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash the password using Argon2id with the generated salt
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	// Encode salt and hash to base64 for storage
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	// Return the combined salt and hash in a single string as "salt$hash" format
	return fmt.Sprintf("%s$%s", encodedSalt, encodedHash), nil
}

// SignUp creates a new user account with the provided username and password
func SignUp(ctx context.Context, db db.Database, username, password string) (iam.User, error) {
	var user iam.User

	// TODO(kompotkot): Add username and password validation

	passwordHash, err := hashPassword(password)
	if err != nil {
		return user, fmt.Errorf("failed to hash password: %w", err)
	}

	user, err = db.CreateUser(ctx, username, passwordHash)
	if err != nil {
		return user, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}
