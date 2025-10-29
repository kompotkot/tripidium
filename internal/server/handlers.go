package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kompotkot/tripidium/internal/service"
)

// Extensible handlers interface
type Handlers interface {
	Ping(w http.ResponseWriter, r *http.Request)
	SignUp(w http.ResponseWriter, r *http.Request)
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
	Id        int64     `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Ping handles the ping-pong endpoint
func (h *handlers) Ping(w http.ResponseWriter, r *http.Request) {
	h.deps.Log.Info("internal.server.handlers.Ping", "method", r.Method, "path", r.URL.Path)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

// SignUp handles new user registrations
func (h *handlers) SignUp(w http.ResponseWriter, r *http.Request) {
	h.deps.Log.Info("internal.server.handlers.SignUp", "method", r.Method, "path", r.URL.Path)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.deps.Log.Error("internal.server.handlers.SignUp", "error", err)
		http.Error(w, "Failed to parse the form", http.StatusBadGateway)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := service.SignUp(r.Context(), h.deps.DB, username, password)
	if err != nil {
		h.deps.Log.Error("internal.server.handlers.SignUp", "error", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	response := UserResponse{
		Id:        user.Id,
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	json.NewEncoder(w).Encode(response)
}

func (h *handlers) User(w http.ResponseWriter, r *http.Request) {
	h.deps.Log.Info("internal.server.handlers.User", "method", r.Method, "path", r.URL.Path)

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenIdStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenIdStr == "" {
		http.Error(w, "Token is required", http.StatusUnauthorized)
		return
	}

	tokenId, err := strconv.ParseInt(tokenIdStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid token format", http.StatusBadRequest)
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
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	json.NewEncoder(w).Encode(response)
}
