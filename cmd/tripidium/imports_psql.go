//go:build psql

package main

import (
	_ "github.com/kompotkot/tripidium/pkg/db/psql" // Import to register PostgreSQL factory
)
