package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kompotkot/tripidium/internal/service"
)

// Extensible handlers interface
type Handlers interface {
	Ping(w http.ResponseWriter, r *http.Request)
	Health(w http.ResponseWriter, r *http.Request)

	SignUp(w http.ResponseWriter, r *http.Request)
	AuthLogin(w http.ResponseWriter, r *http.Request)
	AuthRefresh(w http.ResponseWriter, r *http.Request)
	AuthLogout(w http.ResponseWriter, r *http.Request)
	AuthSessionsList(w http.ResponseWriter, r *http.Request)
	AuthSessionsRevokeAll(w http.ResponseWriter, r *http.Request)
	AuthSessionRevokeOne(w http.ResponseWriter, r *http.Request)

	User(w http.ResponseWriter, r *http.Request)
	UserPatch(w http.ResponseWriter, r *http.Request)
	UserPasswordPut(w http.ResponseWriter, r *http.Request)
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
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Ping handles the ping-pong endpoint
func (h *handlers) Ping(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

// Health returns a minimal service health payload with response time
func (h *handlers) Health(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	body := map[string]any{
		"status":         "ok",
		// TODO(kompotkot): move such settings to configuration
		"response_time_ms": time.Since(start).Milliseconds(),
	}
	_ = json.NewEncoder(w).Encode(body)
}

func notImplemented(w http.ResponseWriter) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (h *handlers) AuthLogin(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}

func (h *handlers) AuthRefresh(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}

func (h *handlers) AuthLogout(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}

func (h *handlers) AuthSessionsList(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}

func (h *handlers) AuthSessionsRevokeAll(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}

func (h *handlers) AuthSessionRevokeOne(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}

func (h *handlers) UserPatch(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}

func (h *handlers) UserPasswordPut(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}

// SignUp handles new user registrations
func (h *handlers) SignUp(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.deps.Log.Error("signup_parse_failed", "error", err)
		http.Error(w, "Failed to parse the form", http.StatusBadGateway)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := service.SignUp(r.Context(), h.deps.DB, username, password)
	if err != nil {
		h.deps.Log.Error("signup_failed", "error", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	response := UserResponse{
		Id:        user.ID.String(),
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	json.NewEncoder(w).Encode(response)
}

func (h *handlers) User(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	sessionIDStr := strings.TrimPrefix(authHeader, "Bearer ")
	if sessionIDStr == "" {
		http.Error(w, "Token is required", http.StatusUnauthorized)
		return
	}

	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		http.Error(w, "Invalid session ID", http.StatusUnauthorized)
		return
	}

	token, err := h.deps.DB.GetAuthSession(r.Context(), sessionID)
	if err != nil {
		h.deps.Log.Error("get_user_auth_failed", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	user, err := h.deps.DB.GetUser(r.Context(), token.UserID.String(), "")
	if err != nil {
		h.deps.Log.Error("get_user_failed", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	response := UserResponse{
		Id:        user.ID.String(),
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	json.NewEncoder(w).Encode(response)
}
