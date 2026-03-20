package types

import (
	"crypto/ed25519"
	"time"
)

// Logger configuration
type LoggerConfig struct {
	Level  string
	Format string
}

// Database configuration
type DatabaseConfig struct {
	Type            string
	URI             string
	MaxConns        int
	ConnMaxLifetime time.Duration
}

// Server configuration
type ServerConfig struct {
	Addr                      string
	Port                      string
	CORSWhitelist             map[string]bool
	CORSAllowedDefaultMethods string
	AccessTokenPrivateKey     ed25519.PrivateKey
	AccessSessionTTL          time.Duration
}

// Main configuration
type Config struct {
	Logger   LoggerConfig
	Database DatabaseConfig
	Server   ServerConfig
}
