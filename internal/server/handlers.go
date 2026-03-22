package server

import (
	"encoding/json"
	"errors"
	"net"
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

	GetUser(w http.ResponseWriter, r *http.Request)
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

	phone, err := service.ValidatePhone(phoneRaw, h.deps.Cfg.IsPhoneRequired)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	passwordHash, err := service.HashPassword(password, h.deps.Cfg.AuthConfig)
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
		h.deps.Log.Error("login_parse_failed", "error", err)
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

	if !user.IsActive {
		http.Error(w, "User is not active", http.StatusUnauthorized)
		return
	}

	// Verify password

	ok, err := service.VerifyPassword(password, user.PasswordHash, h.deps.Cfg.AuthConfig)
	if err != nil {
		h.deps.Log.Error("login_verify_password_failed", "error", err)
		http.Error(w, "Failed to verify password", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create refresh token pair

	refreshToken, refreshTokenHash, err := service.CreateRefreshTokenPair(h.deps.Cfg.AuthConfig)
	if err != nil {
		h.deps.Log.Error("login_refresh_token_create_failed", "error", err)
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
		return
	}

	// Parse client IP, user agent and create auth session

	clientIP := r.RemoteAddr
	if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
		clientIP = host
	}

	userAgentRaw := r.UserAgent()
	var userAgent *string
	if userAgentRaw != "" {
		userAgent = &userAgentRaw
	}

	sessionID := uuid.New()
	familyID := uuid.New()

	expiresAt := time.Now().UTC().Add(h.deps.Cfg.AuthConfig.AccessSessionTTL)

	session, err := h.deps.DB.CreateAuthSession(r.Context(), sessionID, user.ID, familyID, refreshTokenHash, clientIP, userAgent, expiresAt)
	if err != nil {
		h.deps.Log.Error("login_create_session_failed", "error", err)
		http.Error(w, "Failed to create auth session", http.StatusInternalServerError)
		return
	}

	// Issue access token

	accessToken, err := service.CreateAccessToken(user.ID, session.ID, h.deps.Cfg.AuthConfig)
	if err != nil {
		h.deps.Log.Error("login_access_token_create_failed", "error", err)
		http.Error(w, "Failed to create access token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.deps.Cfg.AuthConfig.RefreshTokenCookieName,
		Value:    refreshToken,
		Path:     h.deps.Cfg.AuthConfig.RefreshTokenCookiePath,
		Domain:   h.deps.Cfg.AuthConfig.RefreshTokenCookieDomain,
		Expires:  expiresAt,
		HttpOnly: h.deps.Cfg.AuthConfig.RefreshTokenCookieHttpOnly,
		Secure:   h.deps.Cfg.AuthConfig.RefreshTokenCookieSecure,
		SameSite: h.deps.Cfg.AuthConfig.RefreshTokenCookieSameSite,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ToAuthLoginResponse(accessToken, ""))
}

func (h *handlers) AuthRefresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.deps.Cfg.AuthConfig.RefreshTokenCookieName)
	if err != nil {
		http.Error(w, "missing refresh token", http.StatusUnauthorized)
		return
	}

	// Validate length of refresh token and get hash

	refreshToken, err := service.ValidateLengthOfRefreshToken(cookie.Value, h.deps.Cfg.AuthConfig)
	if err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	refreshTokenHash := service.HashRefreshToken(refreshToken)

	clientIP := r.RemoteAddr
	if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
		clientIP = host
	}

	userAgentRaw := r.UserAgent()
	var userAgent *string
	if userAgentRaw != "" {
		userAgent = &userAgentRaw
	}

	newSessionID := uuid.New()
	expiresAt := time.Now().UTC().Add(h.deps.Cfg.AuthConfig.AccessSessionTTL)
	newRefreshToken, newRefreshTokenHash, err := service.CreateRefreshTokenPair(h.deps.Cfg.AuthConfig)
	if err != nil {
		h.deps.Log.Error("refresh_token_create_failed", "error", err)
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
		return
	}

	newSession, err := h.deps.DB.RefreshAuthSession(r.Context(), refreshTokenHash, newSessionID, newRefreshTokenHash, clientIP, userAgent, expiresAt)
	if err != nil {
		if errors.Is(err, db.ErrTokenNotFound) || errors.Is(err, db.ErrTokenExpired) || errors.Is(err, db.ErrTokenReuseDetected) || errors.Is(err, db.ErrUserNotFound) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.deps.Log.Error("refresh_rotate_session_failed", "error", err)
		http.Error(w, "Failed to rotate auth session", http.StatusInternalServerError)
		return
	}

	accessToken, err := service.CreateAccessToken(newSession.UserID, newSession.ID, h.deps.Cfg.AuthConfig)
	if err != nil {
		h.deps.Log.Error("refresh_access_token_create_failed", "error", err)
		http.Error(w, "Failed to create access token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.deps.Cfg.AuthConfig.RefreshTokenCookieName,
		Value:    newRefreshToken,
		Path:     h.deps.Cfg.AuthConfig.RefreshTokenCookiePath,
		Domain:   h.deps.Cfg.AuthConfig.RefreshTokenCookieDomain,
		Expires:  expiresAt,
		HttpOnly: h.deps.Cfg.AuthConfig.RefreshTokenCookieHttpOnly,
		Secure:   h.deps.Cfg.AuthConfig.RefreshTokenCookieSecure,
		SameSite: h.deps.Cfg.AuthConfig.RefreshTokenCookieSameSite,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ToAuthLoginResponse(accessToken, ""))
}

func (h *handlers) AuthLogout(w http.ResponseWriter, r *http.Request) {
	userID, ok := authUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	sessionIDRaw, ok := authSessionIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	sessionID, err := uuid.Parse(sessionIDRaw)
	if err != nil {
		h.deps.Log.Error("logout_invalid_session_id", "user_id", userID, "session_id", sessionIDRaw, "error", err)
		http.Error(w, "Invalid session id", http.StatusInternalServerError)
		return
	}

	if err := h.deps.DB.RevokeAuthSession(r.Context(), sessionID, "logout", nil); err != nil {
		h.deps.Log.Error("logout_revoke_session_failed", "user_id", userID, "session_id", sessionIDRaw, "error", err)
		http.Error(w, "Failed to revoke auth session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.deps.Cfg.AuthConfig.RefreshTokenCookieName,
		Value:    "",
		Path:     h.deps.Cfg.AuthConfig.RefreshTokenCookiePath,
		Domain:   h.deps.Cfg.AuthConfig.RefreshTokenCookieDomain,
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: h.deps.Cfg.AuthConfig.RefreshTokenCookieHttpOnly,
		Secure:   h.deps.Cfg.AuthConfig.RefreshTokenCookieSecure,
		SameSite: h.deps.Cfg.AuthConfig.RefreshTokenCookieSameSite,
	})

	w.WriteHeader(http.StatusNoContent)
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

func (h *handlers) GetUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := authUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := h.deps.DB.GetUser(r.Context(), userID, "", "")
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.deps.Log.Error("get_user_failed", "user_id", userID, "error", err)
		http.Error(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	if !user.IsActive {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ToUserResponse(user))
}

func (h *handlers) UserPatch(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}

func (h *handlers) UserPasswordPut(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}
