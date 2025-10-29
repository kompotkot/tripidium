package types

import "time"

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
}

// Main configuration
type Config struct {
	Logger   LoggerConfig
	Database DatabaseConfig
	Server   ServerConfig
}
