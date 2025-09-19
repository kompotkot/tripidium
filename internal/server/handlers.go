package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Extensible handlers interface
type Handlers interface {
	Ping(w http.ResponseWriter, r *http.Request)
	User(w http.ResponseWriter, r *http.Request)
}

// handlers holds handlers with dependencies
type handlers struct {
	deps Dependencies
}

// NewHandlers creates a new handlers instance with dependencies
func NewHandlers(deps Dependencies) Handlers {
	return &handlers{deps: deps}
}

type UserResponse struct {
	Id        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Ping handles the ping-pong endpoint
func (h *handlers) Ping(w http.ResponseWriter, r *http.Request) {
	h.deps.Log.Info("internal.server.handlers.Ping", "method", r.Method, "path", r.URL.Path)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

func (h *handlers) User(w http.ResponseWriter, r *http.Request) {
	h.deps.Log.Info("internal.server.handlers.User", "method", r.Method, "path", r.URL.Path)

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenId := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenId == "" {
		http.Error(w, "Token is required", http.StatusUnauthorized)
		return
	}

	token, err := h.deps.DB.GetToken(r.Context(), tokenId)
	if err != nil {
		h.deps.Log.Error("internal.server.handlers.Logout", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	user, err := h.deps.DB.GetUser(r.Context(), token.UserId, "")
	if err != nil {
		h.deps.Log.Error("internal.server.handlers.User", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	response := UserResponse{
		Id:        user.Id,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	json.NewEncoder(w).Encode(response)
}
