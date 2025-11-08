//go:build sqlite

package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kompotkot/tripidium/pkg/iam"

	_ "github.com/mattn/go-sqlite3"
)

// validSyncModes lists the allowed values for the synchronous pragma
var validSyncModes = map[string]bool{
	"OFF":    true,
	"NORMAL": true,
	"FULL":   true,
	"EXTRA":  true,
}

// SqliteDB represents a SQLite database connection
type SqliteDB struct {
	db *sql.DB
}

// NewSqliteDB creates a new SQLite database connection with specified options
func NewSqliteDB(uri string, enableWal bool, syncPragma string) (*SqliteDB, error) {
	params := url.Values{}

	if enableWal {
		params.Add("_journal_mode", "WAL")
	}

	if syncPragma != "" {
		ucSyncPragma := strings.ToUpper(syncPragma)
		if !validSyncModes[ucSyncPragma] {
			return nil, fmt.Errorf("invalid sync pragma value: %s. Must be one of OFF, NORMAL, FULL, EXTRA", syncPragma)
		}
		params.Add("_synchronous", ucSyncPragma)
	}

	constructedUri := uri
	if len(params) > 0 {
		if strings.Contains(uri, "?") {
			constructedUri += "&" + params.Encode()
		} else {
			constructedUri += "?" + params.Encode()
		}
	}

	db, err := sql.Open("sqlite3", constructedUri)
	if err != nil {
		return nil, fmt.Errorf("failed to open database with DSN '%s': %w", constructedUri, err)
	}

	// Configure connection pool settings
	db.SetMaxOpenConns(1) // SQLite only supports one writer at a time
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	// Enable foreign key support for this connection.
	// This is crucial for ON DELETE CASCADE and other FK actions to work.
	_, err = db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		db.Close() // Close DB if we can't set the pragma
		return nil, fmt.Errorf("failed to enable foreign key support for DSN '%s': %w", constructedUri, err)
	}

	return &SqliteDB{db: db}, nil
}

// TestConnection tests the database connection with a timeout
func (s *SqliteDB) TestConnection(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return s.db.PingContext(ctx)
}

// Close closes the database connection
func (s *SqliteDB) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (p *SqliteDB) CreateUser(ctx context.Context, username, passwordHash string) (iam.User, error) {
	return iam.User{}, nil
}

func (p *SqliteDB) GetUser(ctx context.Context, userId, username string) (iam.User, error) {
	return iam.User{}, nil
}

func (p *SqliteDB) GetToken(ctx context.Context, tokenId string) (iam.Token, error) {
	return iam.Token{}, nil
}
