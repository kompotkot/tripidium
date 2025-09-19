package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kompotkot/tripidium/internal/types"
)

// Default configuration values
const (
	DefaultLoggerLevel  = "info"
	DefaultLoggerFormat = "text"

	DefaultDatabaseURI             = "postgres://postgres:postgres@localhost:5432/postgres"
	DefaultDatabaseMaxConns        = 10
	DefaultDatabaseConnMaxLifetime = 30 * time.Second

	DefaultServerAddr                = "localhost"
	DefaultServerPort                = "8080"
	DefaultCORSAllowedDefaultMethods = "GET, OPTIONS"
)

// Load and parse configuration
// TODO(kompotkot): Re-write based on https://github.com/kelseyhightower/envconfig
func Load() (*types.Config, error) {
	var cfg types.Config

	logLevelEnv := os.Getenv("LOG_LEVEL")
	if logLevelEnv == "" {
		logLevelEnv = DefaultLoggerLevel
	}

	logFormatEnv := os.Getenv("LOG_FORMAT")
	if logFormatEnv == "" {
		logFormatEnv = DefaultLoggerFormat
	}

	databaseURIEnv := os.Getenv("DATABASE_URI")
	if databaseURIEnv == "" {
		databaseURIEnv = DefaultDatabaseURI
	}

	var databaseMaxConns int
	databaseMaxConnsEnv := os.Getenv("DATABASE_MAX_OPEN_CONNS")
	if databaseMaxConnsEnv != "" {
		if val, err := strconv.Atoi(databaseMaxConnsEnv); err != nil {
			return nil, fmt.Errorf("invalid max open conns: %s, must be a number", databaseMaxConnsEnv)
		} else {
			databaseMaxConns = val
		}
	} else {
		databaseMaxConns = DefaultDatabaseMaxConns
	}

	var databaseConnMaxLifetime time.Duration
	databaseConnMaxLifetimeSecEnv := os.Getenv("DATABASE_CONN_MAX_LIFETIME_SEC")
	if databaseConnMaxLifetimeSecEnv != "" {
		if val, err := strconv.Atoi(databaseConnMaxLifetimeSecEnv); err != nil {
			return nil, fmt.Errorf("invalid conn max lifetime: %s, must be a number", databaseConnMaxLifetimeSecEnv)
		} else {
			databaseConnMaxLifetime = time.Duration(val) * time.Second
		}
	} else {
		databaseConnMaxLifetime = DefaultDatabaseConnMaxLifetime
	}

	serverAddr := os.Getenv("SERVER_ADDR")
	if serverAddr == "" {
		serverAddr = DefaultServerAddr
	}

	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = DefaultServerPort
	} else {
		if _, err := strconv.Atoi(serverPort); err != nil {
			return nil, fmt.Errorf("invalid port: %s, must be a number", serverPort)
		}
	}

	serverCORSWhitelistEnv := os.Getenv("SERVER_CORS_WHITELIST")
	corsWhitelistSls := strings.Split(strings.ReplaceAll(serverCORSWhitelistEnv, " ", ""), ",")
	corsWhitelist := make(map[string]bool, len(corsWhitelistSls))
	for _, uri := range corsWhitelistSls {
		if uri == "*" {
			corsWhitelist = make(map[string]bool, 1)
			corsWhitelist["*"] = true
			break
		}
		valid, err := url.ParseRequestURI(uri)
		if err != nil {
			fmt.Printf("Ignoring incorrect URI %s", uri)
			continue
		}
		corsWhitelist[valid.String()] = true
	}

	serverCORSAllowedDefaultMethodsEnv := os.Getenv("SERVER_CORS_ALLOWED_DEFAULT_METHODS")
	if serverCORSAllowedDefaultMethodsEnv == "" {
		serverCORSAllowedDefaultMethodsEnv = DefaultCORSAllowedDefaultMethods
	}

	cfg = types.Config{
		Logger: types.LoggerConfig{
			Level:  logLevelEnv,
			Format: logFormatEnv,
		},
		Database: types.DatabaseConfig{
			URI:             databaseURIEnv,
			MaxConns:        databaseMaxConns,
			ConnMaxLifetime: databaseConnMaxLifetime,
		},
		Server: types.ServerConfig{
			Addr:                      serverAddr,
			Port:                      serverPort,
			CORSWhitelist:             corsWhitelist,
			CORSAllowedDefaultMethods: serverCORSAllowedDefaultMethodsEnv,
		},
	}

	return &cfg, nil
}
