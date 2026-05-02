package users

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

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

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	subjectID, ok := runtime.AuthUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := h.deps.DB.GetUser(r.Context(), subjectID, "", "")
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.deps.Log.Error("get_user_failed", "subject_id", subjectID, "error", err)
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

func (h *Handler) UserPatch(w http.ResponseWriter, r *http.Request) {
	subjectIDRaw, ok := runtime.AuthUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.deps.Log.Error("user_patch_parse_failed", "subject_id", subjectIDRaw, "error", err)
		http.Error(w, "Failed to parse the form", http.StatusBadRequest)
		return
	}

	currentUser, err := h.deps.DB.GetUser(r.Context(), subjectIDRaw, "", "")
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.deps.Log.Error("user_patch_get_user_failed", "subject_id", subjectIDRaw, "error", err)
		http.Error(w, "Failed to get user", http.StatusInternalServerError)
		return
	}
	if !currentUser.IsActive {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	username := currentUser.Username
	email := currentUser.Email
	phone := 0
	if currentUser.Phone != nil {
		phone = int(*currentUser.Phone)
	}

	if _, provided := r.Form["username"]; provided {
		username, err = service.ValidateUsername(r.FormValue("username"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if _, provided := r.Form["email"]; provided {
		email, err = service.ValidateEmail(r.FormValue("email"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if _, provided := r.Form["phone"]; provided {
		phone, err = service.ValidatePhone(r.FormValue("phone"), h.deps.Cfg.IsPhoneRequired)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if _, hasUsername := r.Form["username"]; !hasUsername {
		if _, hasEmail := r.Form["email"]; !hasEmail {
			if _, hasPhone := r.Form["phone"]; !hasPhone {
				http.Error(w, "At least one field must be provided", http.StatusBadRequest)
				return
			}
		}
	}

	phoneValue := ""
	if phone != 0 {
		phoneValue = strconv.Itoa(phone)
	}

	updatedUser, err := h.deps.DB.UpdateUser(r.Context(), currentUser.ID, username, email, phoneValue)
	if err != nil {
		if errors.Is(err, db.ErrUserAlreadyExists) {
			http.Error(w, "Username or email already exists", http.StatusConflict)
			return
		}
		if errors.Is(err, db.ErrUserNotFound) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.deps.Log.Error("user_patch_update_failed", "user_id", currentUser.ID.String(), "subject_id", subjectIDRaw, "error", err)
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ToUserResponse(updatedUser))
}

func (h *Handler) UserPasswordPut(w http.ResponseWriter, r *http.Request) {
	subjectIDRaw, ok := runtime.AuthUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.deps.Log.Error("user_password_parse_failed", "subject_id", subjectIDRaw, "error", err)
		http.Error(w, "Failed to parse the form", http.StatusBadRequest)
		return
	}

	currentPasswordRaw := r.FormValue("current_password")
	newPasswordRaw := r.FormValue("new_password")
	if currentPasswordRaw == "" || newPasswordRaw == "" {
		http.Error(w, "Current password and new password are required", http.StatusBadRequest)
		return
	}

	currentPassword, err := service.ValidatePassword(currentPasswordRaw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	newPassword, err := service.ValidatePassword(newPasswordRaw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.deps.DB.GetUser(r.Context(), subjectIDRaw, "", "")
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.deps.Log.Error("user_password_get_user_failed", "subject_id", subjectIDRaw, "error", err)
		http.Error(w, "Failed to get user", http.StatusInternalServerError)
		return
	}
	if !user.IsActive {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ok, err = service.VerifyPassword(currentPassword, user.PasswordHash, h.deps.Cfg.AuthConfig)
	if err != nil {
		h.deps.Log.Error("user_password_verify_failed", "user_id", user.ID.String(), "subject_id", subjectIDRaw, "error", err)
		http.Error(w, "Failed to verify current password", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Current password is incorrect", http.StatusBadRequest)
		return
	}

	passwordHash, err := service.HashPassword(newPassword, h.deps.Cfg.AuthConfig)
	if err != nil {
		h.deps.Log.Error("user_password_hash_failed", "user_id", user.ID.String(), "subject_id", subjectIDRaw, "error", err)
		http.Error(w, "Failed to hash new password", http.StatusInternalServerError)
		return
	}

	userID := user.ID
	if userID == uuid.Nil {
		h.deps.Log.Error("user_password_empty_user_id", "subject_id", subjectIDRaw)
		http.Error(w, "Invalid user id", http.StatusInternalServerError)
		return
	}

	if err := h.deps.DB.UpdateUserPassword(r.Context(), userID, passwordHash); err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.deps.Log.Error("user_password_update_failed", "user_id", userID.String(), "subject_id", subjectIDRaw, "error", err)
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
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
