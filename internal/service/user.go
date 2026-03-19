package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/mail"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// TODO(kompotkot): Move to configuration
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	saltLen      int    = 16

	isPhoneRequired bool = false
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
func ValidatePhone(phoneRaw string) (int, error) {
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
func HashPassword(password string) (string, error) {
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

// VerifyPassword checks whether the provided password matches the stored salt$hash value.
func VerifyPassword(password, passwordHash string) (bool, error) {
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
		argonTime,
		argonMemory,
		argonThreads,
		uint32(len(expectedHash)),
	)

	match := subtle.ConstantTimeCompare(computedHash, expectedHash) == 1
	return match, nil
}
