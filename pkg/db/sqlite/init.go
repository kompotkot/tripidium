//go:build sqlite

package sqlite

import (
	"github.com/kompotkot/tripidium/pkg/db"
)

func init() {
	// Register SQLite factory when this package is imported
	db.RegisterDatabase(NewFactory())
}
