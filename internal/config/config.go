package config

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
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

	DefaultDatabaseType            = "sqlite"
	DefaultDatabaseSqliteURI       = "tripidium.sqlite"
	DefaultDatabasePsqlURI         = "postgres://postgres:postgres@localhost:5432/tripidium"
	DefaultDatabaseMaxConns        = 10
	DefaultDatabaseConnMaxLifetime = 30 * time.Second

	// Server defaults
	DefaultServerAddr           = "localhost"
	DefaultServerPort           = "8080"
	DefaultIsPhoneRequired bool = false

	DefaultCORSAllowedDefaultMethods = "GET,POST,PATCH,PUT,DELETE,OPTIONS"

	// Argon defaults
	DefaultArgonTime    uint32 = 1
	DefaultArgonMemory  uint32 = 64 * 1024
	DefaultArgonThreads uint8  = 4
	DefaultArgonKeyLen  uint32 = 32
	DefaultSaltLen      int    = 16

	// JWT defaults
	DefaultAccessTokenPrivateKeyFilePath = "access_token_private_key.pem"

	DefaultAccessSessionTTL    time.Duration = 7 * 24 * time.Hour
	DefaultAccessTokenTTL      time.Duration = 5 * time.Minute
	DefaultAccessTokenIssuer                 = "auth.tripidium"
	DefaultAccessTokenAudience               = "api.tripidium"
	DefaultAccessTokenKid                    = "ed25519-v1" // TODO(kompotkot): Add rotation of access token kid logic
	DefaultAccessTokenTyp                    = "access+jwt"
	DefaultRefreshTokenLen     int           = 32
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

	databaseTypeEnv := os.Getenv("DATABASE_TYPE")
	if databaseTypeEnv == "" {
		databaseTypeEnv = DefaultDatabaseType
	}

	databaseURIEnv := os.Getenv("DATABASE_URI")
	if databaseURIEnv == "" {
		switch databaseTypeEnv {
		case "psql":
			databaseURIEnv = DefaultDatabasePsqlURI
		case "sqlite":
			databaseURIEnv = DefaultDatabaseSqliteURI
		default:
			return nil, fmt.Errorf("invalid database type: %s", databaseTypeEnv)
		}
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

	accessTokenPrivateKeyFilePathEnv := os.Getenv("ACCESS_TOKEN_PRIVATE_KEY_FILE_PATH")
	if accessTokenPrivateKeyFilePathEnv == "" {
		accessTokenPrivateKeyFilePathEnv = DefaultAccessTokenPrivateKeyFilePath
	}

	accessTokenPrivateKeyFile, err := os.ReadFile(accessTokenPrivateKeyFilePathEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to read access token private key file: %v", err)
	}
	block, _ := pem.Decode(accessTokenPrivateKeyFile)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM access token private key")
	}
	parsedPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 access token private key: %v", err)
	}
	accessTokenPrivateKey, ok := parsedPrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("access token private key is not ed25519")
	}

	var accessSessionTTL time.Duration
	accessSessionTTLEnv := os.Getenv("ACCESS_SESSION_TTL_SEC")
	if accessSessionTTLEnv != "" {
		if val, err := strconv.Atoi(accessSessionTTLEnv); err != nil {
			fmt.Printf("Ignoring incorrect access session TTL: %s, must be a number", accessSessionTTLEnv)
			accessSessionTTL = DefaultAccessSessionTTL
		} else {
			accessSessionTTL = time.Duration(val) * time.Second
		}
	} else {
		accessSessionTTL = DefaultAccessSessionTTL
	}

	cfg = types.Config{
		Logger: types.LoggerConfig{
			Level:  logLevelEnv,
			Format: logFormatEnv,
		},
		Database: types.DatabaseConfig{
			Type:            databaseTypeEnv,
			URI:             databaseURIEnv,
			MaxConns:        databaseMaxConns,
			ConnMaxLifetime: databaseConnMaxLifetime,
		},
		Server: types.ServerConfig{
			Addr: serverAddr,
			Port: serverPort,

			IsPhoneRequired: DefaultIsPhoneRequired,

			CORSWhitelist:             corsWhitelist,
			CORSAllowedDefaultMethods: serverCORSAllowedDefaultMethodsEnv,

			AuthConfig: types.AuthConfig{
				ArgonTime:    DefaultArgonTime,
				ArgonMemory:  DefaultArgonMemory,
				ArgonThreads: DefaultArgonThreads,
				ArgonKeyLen:  DefaultArgonKeyLen,
				SaltLen:      DefaultSaltLen,

				AccessSessionTTL:      accessSessionTTL,
				AccessTokenPrivateKey: accessTokenPrivateKey,
				AccessTokenTTL:        DefaultAccessTokenTTL,
				AccessTokenIssuer:     DefaultAccessTokenIssuer,
				AccessTokenAudience:   DefaultAccessTokenAudience,
				AccessTokenKid:        DefaultAccessTokenKid,
				AccessTokenTyp:        DefaultAccessTokenTyp,
				RefreshTokenLen:       DefaultRefreshTokenLen,
			},
		},
	}

	return &cfg, nil
}
