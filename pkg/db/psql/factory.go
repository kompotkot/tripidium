//go:build psql

package psql

import (
	"time"

	"github.com/kompotkot/tripidium/pkg/db"
)

// Factory implements DatabaseFactory for PostgreSQL
type Factory struct{}

// NewFactory creates a new PostgreSQL factory
func NewFactory() db.DatabaseFactory {
	return &Factory{}
}

// Create creates a new PostgreSQL database connection
func (f *Factory) Create(uri string, maxConns int, connMaxLifetime int64) (db.Database, error) {
	return NewPsqlDB(uri, maxConns, time.Duration(connMaxLifetime))
}

// GetType returns the database type
func (f *Factory) GetType() string {
	return "postgresql"
}
