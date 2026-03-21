package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	"github.com/kompotkot/tripidium/internal/types"
)

// ValidateUsername validates the username
func ValidateUsername(usernameRaw string) (string, error) {
	username := strings.TrimSpace(usernameRaw)
	if len(username) < 3 || len(username) > 32 {
		return "", fmt.Errorf("username must be between 3 and 32 characters")
	}
	return username, nil
}

// ValidatePassword validates the password
func ValidatePassword(passwordRaw string) (string, error) {
	password := strings.TrimSpace(passwordRaw)
	if len(password) < 8 || len(password) > 64 {
		return "", fmt.Errorf("password must be between 8 and 64 characters")
	}
	return password, nil
}

// ValidateEmail validates the email
func ValidateEmail(emailRaw string) (string, error) {
	email := strings.TrimSpace(emailRaw)

	emailAddress, err := mail.ParseAddress(email)
	if err != nil {
		return "", fmt.Errorf("failed to parse email: %w", err)
	}
	return emailAddress.Address, nil
}

// ValidatePhone validates the phone number
func ValidatePhone(phoneRaw string, isPhoneRequired bool) (int, error) {
	// If phone is not required, then empty allowed
	if !isPhoneRequired && phoneRaw == "" {
		return 0, nil
	}

	phone := strings.TrimSpace(phoneRaw)

	if len(phone) < 10 || len(phone) > 15 {
		return 0, fmt.Errorf("phone must be between 10 and 15 characters")
	}

	if phone[0] == '+' {
		phone = phone[1:]
	}

	phoneNumber, err := strconv.Atoi(phone)
	if err != nil {
		return 0, fmt.Errorf("failed to convert phone to number: %w", err)
	}

	return phoneNumber, nil
}

// HashPassword securely hashes a password using Argon2 algorithm
func HashPassword(password string, authConfig types.AuthConfig) (string, error) {
	// Generate a random salt for password hashing
	salt := make([]byte, authConfig.SaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash the password using Argon2id with the generated salt
	hash := argon2.IDKey([]byte(password), salt, authConfig.ArgonTime, authConfig.ArgonMemory, authConfig.ArgonThreads, authConfig.ArgonKeyLen)

	// Encode salt and hash to base64 for storage
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	// Return the combined salt and hash in a single string as "salt$hash" format
	return fmt.Sprintf("%s$%s", encodedSalt, encodedHash), nil
}

// VerifyPassword checks whether the provided password matches the stored salt$hash value.
func VerifyPassword(password, passwordHash string, authConfig types.AuthConfig) (bool, error) {
	parts := strings.Split(passwordHash, "$")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid stored password hash format")
	}

	encodedSalt := parts[0]
	encodedHash := parts[1]

	salt, err := base64.RawStdEncoding.DecodeString(encodedSalt)
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(encodedHash)
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		authConfig.ArgonTime,
		authConfig.ArgonMemory,
		authConfig.ArgonThreads,
		uint32(len(expectedHash)),
	)

	match := subtle.ConstantTimeCompare(computedHash, expectedHash) == 1
	return match, nil
}

// AccessTokenClaims contains custom access token claims
type AccessTokenClaims struct {
	SessionID string `json:"sid"`
	jwt.RegisteredClaims
}

// CreateAccessToken creates and signs a short-lived JWT access token
func CreateAccessToken(userID, sessionID uuid.UUID, authConfig types.AuthConfig) (string, error) {
	now := time.Now().UTC()
	claims := AccessTokenClaims{
		SessionID: sessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Issuer:    authConfig.AccessTokenIssuer,
			Audience:  jwt.ClaimStrings{authConfig.AccessTokenAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(authConfig.AccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = authConfig.AccessTokenKid
	token.Header["typ"] = authConfig.AccessTokenTyp

	signedToken, err := token.SignedString(authConfig.AccessTokenPrivateKey)
	if err != nil {
		return "", fmt.Errorf("sign access token error: %w", err)
	}
	return signedToken, nil
}

// CreateRefreshTokenPair creates an opaque refresh token and its DB-safe hash
func CreateRefreshTokenPair(authConfig types.AuthConfig) (refreshToken string, refreshTokenHash string, err error) {
	raw := make([]byte, authConfig.RefreshTokenLen)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate refresh token error: %w", err)
	}

	refreshToken = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(refreshToken))
	refreshTokenHash = base64.RawURLEncoding.EncodeToString(sum[:])
	return refreshToken, refreshTokenHash, nil
}
