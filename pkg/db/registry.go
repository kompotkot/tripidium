package db

import (
	"fmt"
)

// DatabaseFactory handles database initialization
type DatabaseFactory interface {
	Create(uri string, maxConns int, connMaxLifetime int64) (Database, error)
	GetType() string
}

var databaseFactories = make(map[string]DatabaseFactory)

// RegisterDatabase adds a database factory to the registry
func RegisterDatabase(factory DatabaseFactory) {
	databaseFactories[factory.GetType()] = factory
}

// CreateDatabase creates a database connection using the appropriate factory
func CreateDatabase(dbType, uri string, maxConns int, connMaxLifetime int64) (Database, error) {
	factory, exists := databaseFactories[dbType]
	if !exists {
		// Collect list of available types for error
		available := make([]string, 0, len(databaseFactories))
		for dbType := range databaseFactories {
			available = append(available, dbType)
		}
		return nil, fmt.Errorf("unsupported database type: %s. Available types: %v", dbType, available)
	}

	return factory.Create(uri, maxConns, connMaxLifetime)
}

// GetAvailableDatabaseTypes returns a list of available database types
func GetAvailableDatabaseTypes() []string {
	types := make([]string, 0, len(databaseFactories))
	for dbType := range databaseFactories {
		types = append(types, dbType)
	}
	return types
}
