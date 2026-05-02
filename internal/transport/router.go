package transport

import (
	"net/http"

	"github.com/kompotkot/tripidium/internal/transport/auth"
	"github.com/kompotkot/tripidium/internal/transport/invites"
	"github.com/kompotkot/tripidium/internal/transport/organizations"
	"github.com/kompotkot/tripidium/internal/transport/runtime"
	"github.com/kompotkot/tripidium/internal/transport/users"
)

type Dependencies = runtime.Dependencies

// Server holds server state and dependencies
type Server struct {
	deps Dependencies

	auth          *auth.Handler
	invites       *invites.Handler
	organizations *organizations.Handler
	users         *users.Handler
}

// NewServer creates a new server instance with dependencies
func NewServer(deps Dependencies) *Server {
	return &Server{
		deps:          deps,
		auth:          auth.NewHandler(deps),
		invites:       invites.NewHandler(deps),
		organizations: organizations.NewHandler(deps),
		users:         users.NewHandler(deps),
	}
}

// BuildCommonHandler creates and configures the HTTP mux with all routes
func (s *Server) BuildCommonHandler() *http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /ping", s.ping)
	mux.HandleFunc("GET /health", s.health)

	mux.HandleFunc("POST /auth/signup", s.auth.AuthSignUp)
	mux.HandleFunc("POST /auth/login", s.auth.AuthLogin)
	mux.HandleFunc("POST /auth/refresh", s.auth.AuthRefresh)
	mux.Handle("POST /auth/logout", s.authMiddleware(http.HandlerFunc(s.auth.AuthLogout)))
	mux.Handle("GET /auth/sessions", s.authMiddleware(http.HandlerFunc(s.auth.AuthSessionsList)))
	mux.HandleFunc("DELETE /auth/sessions", s.auth.AuthSessionsRevokeAll)
	mux.HandleFunc("DELETE /auth/sessions/{session_id}", s.auth.AuthSessionRevokeOne)

	mux.Handle("GET /user", s.authMiddleware(http.HandlerFunc(s.users.GetUser)))
	mux.Handle("PATCH /user", s.authMiddleware(http.HandlerFunc(s.users.UserPatch)))
	mux.Handle("PUT /user/password", s.authMiddleware(http.HandlerFunc(s.users.UserPasswordPut)))

	commonHandler := s.loggerMiddleware(mux)
	commonHandler = s.corsMiddleware(commonHandler)
	commonHandler = s.panicMiddleware(commonHandler)

	return &commonHandler
}
