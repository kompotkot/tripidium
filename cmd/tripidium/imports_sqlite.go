//go:build sqlite

package main

import (
	_ "github.com/kompotkot/tripidium/pkg/db/sqlite" // Import to register SQLite factory
)
