package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/kompotkot/tripidium/internal/service"
	"github.com/kompotkot/tripidium/pkg/db"
)

// Extensible handlers interface
type Handlers interface {
	Ping(w http.ResponseWriter, r *http.Request)
	Health(w http.ResponseWriter, r *http.Request)

	AuthSignUp(w http.ResponseWriter, r *http.Request)
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
		"status": "ok",
		// TODO(kompotkot): move such settings to configuration
		"response_time_ms": time.Since(start).Milliseconds(),
	}
	_ = json.NewEncoder(w).Encode(body)
}

// SignUp handles new user registrations
func (h *handlers) AuthSignUp(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.deps.Log.Error("signup_parse_failed", "error", err)
		http.Error(w, "Failed to parse the form", http.StatusBadGateway)
		return
	}

	usernameRaw := r.FormValue("username")
	emailRaw := r.FormValue("email")
	passwordRaw := r.FormValue("password")
	phoneRaw := r.FormValue("phone")

	if usernameRaw == "" || emailRaw == "" || passwordRaw == "" {
		http.Error(w, "Username, email and password are required", http.StatusBadRequest)
		return
	}

	// Validate input

	username, err := service.ValidateUsername(usernameRaw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email, err := service.ValidateEmail(emailRaw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	password, err := service.ValidatePassword(passwordRaw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	phone, err := service.ValidatePhone(phoneRaw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	passwordHash, err := service.HashPassword(password)
	if err != nil {
		h.deps.Log.Error("signup_hash_password_failed", "error", err)
		http.Error(w, "Failed to hash password", http.StatusBadRequest)
		return
	}

	// Create new user

	userID := uuid.New()
	isActive := true

	user, err := h.deps.DB.CreateUser(r.Context(), userID, isActive, username, email, passwordHash, phone)
	if err != nil {
		h.deps.Log.Error("signup_create_user_failed", "error", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ToUserResponse(user))
}

func notImplemented(w http.ResponseWriter) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (h *handlers) AuthLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.deps.Log.Error("signup_parse_failed", "error", err)
		http.Error(w, "Failed to parse the form", http.StatusBadGateway)
		return
	}

	usernameRaw := r.FormValue("username")
	emailRaw := r.FormValue("email")
	passwordRaw := r.FormValue("password")

	if usernameRaw == "" && emailRaw == "" {
		http.Error(w, "Username or email is required", http.StatusBadRequest)
		return
	}

	// Validate input

	var username, email string
	var err error

	if usernameRaw != "" {
		username, err = service.ValidateUsername(usernameRaw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if emailRaw != "" {
		email, err = service.ValidateEmail(emailRaw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	password, err := service.ValidatePassword(passwordRaw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get user by username or email

	user, err := h.deps.DB.GetUser(r.Context(), "", username, email)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		h.deps.Log.Error("login_get_user_failed", "error", err)
		http.Error(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	// Verify password

	ok, err := service.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		h.deps.Log.Error("login_verify_password_failed", "error", err)
		http.Error(w, "Failed to verify password", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// TODO(kompotkot): Start session

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ToUserResponse(user))
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

func (h *handlers) User(w http.ResponseWriter, r *http.Request) {
	notImplemented(w)
}

func (h *handlers) UserPatch(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}

func (h *handlers) UserPasswordPut(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}
