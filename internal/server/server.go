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

	mux.HandleFunc("GET /ping", h.Ping)
	mux.HandleFunc("GET /health", h.Health)

	mux.HandleFunc("POST /auth/signup", h.AuthSignUp)
	mux.HandleFunc("POST /auth/login", h.AuthLogin)
	mux.HandleFunc("POST /auth/refresh", h.AuthRefresh)
	mux.HandleFunc("POST /auth/logout", h.AuthLogout)
	mux.HandleFunc("GET /auth/sessions", h.AuthSessionsList)
	mux.HandleFunc("DELETE /auth/sessions", h.AuthSessionsRevokeAll)
	mux.HandleFunc("DELETE /auth/sessions/{session_id}", h.AuthSessionRevokeOne)

	mux.Handle("GET /user", s.authMiddleware(http.HandlerFunc(h.GetUser)))
	mux.HandleFunc("PATCH /user", h.UserPatch)
	mux.HandleFunc("PUT /user/password", h.UserPasswordPut)

	commonHandler := s.loggerMiddleware(mux)
	commonHandler = s.corsMiddleware(commonHandler)
	commonHandler = s.panicMiddleware(commonHandler)

	return &commonHandler
}
