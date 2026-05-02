package auth

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kompotkot/tripidium/internal/model"
	"github.com/kompotkot/tripidium/internal/service"
	"github.com/kompotkot/tripidium/internal/transport/runtime"
	"github.com/kompotkot/tripidium/pkg/db"
	"github.com/kompotkot/tripidium/pkg/dto"
)

type Handler struct {
	deps runtime.Dependencies
}

func NewHandler(deps runtime.Dependencies) *Handler {
	return &Handler{deps: deps}
}

// SignUp handles new user registrations
func (h *Handler) AuthSignUp(w http.ResponseWriter, r *http.Request) {
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

	var inviteCode string
	if h.deps.Cfg.IsInviteRequired {
		inviteCode = r.FormValue("invite_code")
		if inviteCode == "" {
			http.Error(w, "Invite code is required", http.StatusBadRequest)
			return
		}
		invite, err := h.deps.DB.CheckUserInvite(r.Context(), inviteCode)
		if err != nil {
			h.deps.Log.Error("signup_check_user_invite_failed", "error", err)
			http.Error(w, "Failed to check user invite", http.StatusInternalServerError)
			return
		}
		if !invite {
			http.Error(w, "User invite not found", http.StatusNotFound)
			return
		}
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

	if h.deps.Cfg.IsInviteRequired {
		if err := h.deps.DB.ClaimUserInvite(r.Context(), inviteCode, userID); err != nil {
			h.deps.Log.Error("signup_claim_user_invite_failed", "error", err)
			http.Error(w, "Failed to claim user invite", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ToUserResponse(user))
}

func (h *Handler) AuthLogin(w http.ResponseWriter, r *http.Request) {
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

	accessToken, err := service.CreateAccessToken(user.ID, session.ID, session.SubjectKind, h.deps.Cfg.AuthConfig)
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

func (h *Handler) AuthRefresh(w http.ResponseWriter, r *http.Request) {
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

	accessToken, err := service.CreateAccessToken(newSession.SubjectID, newSession.ID, newSession.SubjectKind, h.deps.Cfg.AuthConfig)
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

func (h *Handler) AuthLogout(w http.ResponseWriter, r *http.Request) {
	subjectIDRaw, ok := runtime.AuthUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	sessionIDRaw, ok := runtime.AuthSessionIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	sessionID, err := uuid.Parse(sessionIDRaw)
	if err != nil {
		h.deps.Log.Error("logout_invalid_session_id", "subject_id", subjectIDRaw, "session_id", sessionIDRaw, "error", err)
		http.Error(w, "Invalid session id", http.StatusInternalServerError)
		return
	}

	subjectID, err := uuid.Parse(subjectIDRaw)
	if err != nil {
		h.deps.Log.Error("logout_invalid_subject_id", "subject_id", subjectIDRaw, "error", err)
		http.Error(w, "Invalid subject id", http.StatusInternalServerError)
		return
	}

	if err := h.deps.DB.RevokeAuthSession(r.Context(), sessionID, subjectID, "logout", nil); err != nil {
		if errors.Is(err, db.ErrTokenNotFound) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.deps.Log.Error("logout_revoke_session_failed", "subject_id", subjectIDRaw, "session_id", sessionIDRaw, "error", err)
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

func (h *Handler) AuthSessionsList(w http.ResponseWriter, r *http.Request) {
	subjectIDRaw, ok := runtime.AuthUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	currentSessionID, ok := runtime.AuthSessionIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	subjectID, err := uuid.Parse(subjectIDRaw)
	if err != nil {
		h.deps.Log.Error("sessions_invalid_subject_id", "subject_id", subjectIDRaw, "error", err)
		http.Error(w, "Invalid subject id", http.StatusInternalServerError)
		return
	}

	sessions, err := h.deps.DB.ListAuthSessions(r.Context(), subjectID)
	if err != nil {
		h.deps.Log.Error("sessions_list_failed", "subject_id", subjectIDRaw, "error", err)
		http.Error(w, "Failed to list sessions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ToAuthSessionsResponse(sessions, currentSessionID))
}

func notImplemented(w http.ResponseWriter) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (h *Handler) AuthSessionsRevokeAll(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}

func (h *Handler) AuthSessionRevokeOne(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w)
}

func ToAuthLoginResponse(accessToken, refreshToken string) dto.AuthLoginResponse {
	return dto.AuthLoginResponse{
		AccessToken: accessToken,
	}
}

func ToUserResponse(u model.User) dto.UserResponse {
	user := dto.UserResponse{
		Id:        u.ID.String(),
		Username:  u.Username,
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
	if u.Phone != nil {
		p := int(*u.Phone)
		user.Phone = &p
	}
	return user
}

func ToAuthSessionResponse(s model.AuthSession, currentSessionID string) dto.AuthSessionResponse {
	userAgent := ""
	if s.CreatedUserAgent != nil {
		userAgent = strings.TrimSpace(*s.CreatedUserAgent)
	}

	return dto.AuthSessionResponse{
		Id:        s.ID.String(),
		IsCurrent: s.ID.String() == currentSessionID,
		CreatedAt: s.CreatedAt,
		ExpiresAt: s.ExpiresAt,
		UserAgent: userAgent,
		IP:        normalizeSessionIP(s.CreatedIP.String()),
	}
}

func normalizeSessionIP(raw string) string {
	ip := strings.TrimSpace(raw)
	if ip == "" || ip == "<nil>" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	return parsed.String()
}

func ToAuthSessionsResponse(sessions []model.AuthSession, currentSessionID string) []dto.AuthSessionResponse {
	out := make([]dto.AuthSessionResponse, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, ToAuthSessionResponse(s, currentSessionID))
	}
	return out
}
