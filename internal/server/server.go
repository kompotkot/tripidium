package server

import (
	"log/slog"
	"net/http"

	"github.com/kompotkot/tripidium/internal/types"
	"github.com/kompotkot/tripidium/pkg/db"
)

// Deps holds server dependencies
type Dependencies struct {
	DB  db.Database
	Cfg types.ServerConfig
	Log *slog.Logger
}

// Server holds server state and dependencies
type Server struct {
	deps Dependencies
}

// NewServer creates a new server instance with dependencies
func NewServer(deps Dependencies) *Server {
	return &Server{deps: deps}
}

// BuildCommonHandler creates and configures the HTTP mux with all routes
func (s *Server) BuildCommonHandler() *http.Handler {
	mux := http.NewServeMux()

	// Create handlers with dependencies
	h := NewHandlers(s.deps)

	// Register routes
	mux.HandleFunc("/ping", h.Ping)
	mux.HandleFunc("/user", h.User)

	commonHandler := s.corsMiddleware(mux)

	return &commonHandler
}
