package transport

import (
	"net/http"

	"github.com/kompotkot/tripidium/internal/transport/auth"
	"github.com/kompotkot/tripidium/internal/transport/organizations"
	"github.com/kompotkot/tripidium/internal/transport/runtime"
	"github.com/kompotkot/tripidium/internal/transport/users"
)

type Dependencies = runtime.Dependencies

// Server holds server state and dependencies
type Server struct {
	deps Dependencies

	auth          *auth.Handler
	organizations *organizations.Handler
	users         *users.Handler
}

// NewServer creates a new server instance with dependencies
func NewServer(deps Dependencies) *Server {
	return &Server{
		deps:          deps,
		auth:          auth.NewHandler(deps),
		organizations: organizations.NewHandler(deps),
		users:         users.NewHandler(deps),
	}
}

// BuildCommonHandler creates and configures the HTTP mux with all routes
func (s *Server) BuildCommonHandler() *http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /ping", s.ping)
	mux.HandleFunc("GET /health", s.health)

	// Auth endpoints
	mux.HandleFunc("POST /auth/login", s.auth.AuthLogin)
	mux.HandleFunc("POST /auth/refresh", s.auth.AuthRefresh)
	mux.Handle("POST /auth/logout", s.authMiddleware(http.HandlerFunc(s.auth.AuthLogout)))
	mux.Handle("GET /auth/subject", s.authMiddleware(http.HandlerFunc(s.auth.AuthGetSubject)))
	mux.Handle("GET /auth/sessions", s.authMiddleware(http.HandlerFunc(s.auth.AuthSessionsList)))
	mux.Handle("DELETE /auth/sessions", s.authMiddleware(http.HandlerFunc(s.auth.AuthSessionsRevokeAll)))
	mux.Handle("DELETE /auth/sessions/{session_id}", s.authMiddleware(http.HandlerFunc(s.auth.AuthSessionRevokeOne)))

	// User identity endpoints
	mux.HandleFunc("POST /identity/users", s.users.RegisterUser)
	mux.Handle("GET /identity/users/current", s.authMiddleware(http.HandlerFunc(s.users.GetUser)))
	mux.Handle("PATCH /identity/users/current", s.authMiddleware(http.HandlerFunc(s.users.UserPatch)))
	mux.Handle("PUT /identity/users/current/password", s.authMiddleware(http.HandlerFunc(s.users.UserPasswordPut)))

	// Organization endpoints
	mux.Handle("GET /identity/organizations", s.authMiddleware(http.HandlerFunc(s.organizations.ListOrganizations)))
	mux.Handle("POST /identity/organizations", s.authMiddleware(http.HandlerFunc(s.organizations.CreateOrganization)))
	mux.Handle("GET /identity/organizations/{organization_id}", s.authMiddleware(http.HandlerFunc(s.organizations.GetOrganization)))
	mux.Handle("PATCH /identity/organizations/{organization_id}", s.authMiddleware(http.HandlerFunc(s.organizations.UpdateOrganization)))
	mux.Handle("DELETE /identity/organizations/{organization_id}", s.authMiddleware(http.HandlerFunc(s.organizations.DeleteOrganization)))

	// Membership endpoints
	mux.Handle("GET /identity/organizations/{organization_id}/memberships", s.authMiddleware(http.HandlerFunc(s.organizations.ListMembers)))
	mux.Handle("POST /identity/organizations/{organization_id}/memberships", s.authMiddleware(http.HandlerFunc(s.organizations.AddMember)))
	mux.Handle("GET /identity/organizations/{organization_id}/memberships/{user_id}", s.authMiddleware(http.HandlerFunc(s.organizations.GetMember)))
	mux.Handle("PATCH /identity/organizations/{organization_id}/memberships/{user_id}", s.authMiddleware(http.HandlerFunc(s.organizations.UpdateMemberRole)))
	mux.Handle("DELETE /identity/organizations/{organization_id}/memberships/{user_id}", s.authMiddleware(http.HandlerFunc(s.organizations.RemoveMember)))

	commonHandler := s.loggerMiddleware(mux)
	commonHandler = s.corsMiddleware(commonHandler)
	commonHandler = s.panicMiddleware(commonHandler)

	return &commonHandler
}
