package runtime

import (
	"log/slog"

	"github.com/kompotkot/tripidium/internal/authz"
	"github.com/kompotkot/tripidium/internal/config"
	"github.com/kompotkot/tripidium/pkg/db"
)

type Dependencies struct {
	DB         db.Database
	Cfg        config.ServerConfig
	Log        *slog.Logger
	Authorizer authz.Authorizer
}
