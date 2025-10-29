//go:build sqlite

package sqlite

import (
	"github.com/kompotkot/tripidium/pkg/db"
)

// Factory implements DatabaseFactory for SQLite
type Factory struct{}

// NewFactory creates a new SQLite factory
func NewFactory() db.DatabaseFactory {
	return &Factory{}
}

// Create creates a new SQLite database connection
func (f *Factory) Create(uri string, maxConns int, connMaxLifetime int64) (db.Database, error) {
	return NewSqliteDB(uri, true, "NORMAL")
}

// GetType returns the database type
func (f *Factory) GetType() string {
	return "sqlite"
}
