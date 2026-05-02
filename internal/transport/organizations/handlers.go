package organizations

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/kompotkot/tripidium/internal/transport/runtime"
	"github.com/kompotkot/tripidium/pkg/db"
	"github.com/kompotkot/tripidium/pkg/dto"
	"github.com/kompotkot/tripidium/pkg/model"
)

type Handler struct {
	deps runtime.Dependencies
}

func NewHandler(deps runtime.Dependencies) *Handler {
	return &Handler{deps: deps}
}

// callerMembership returns the requesting user's membership record for the given org.
// Returns false if the caller is not a user-backed subject or is not a member.
func (h *Handler) callerMembership(r *http.Request, orgID uuid.UUID) (model.OrganizationMember, bool) {
	callerIDRaw, ok := runtime.AuthUserIDFromContext(r.Context())
	if !ok {
		return model.OrganizationMember{}, false
	}
	callerID, err := uuid.Parse(callerIDRaw)
	if err != nil {
		return model.OrganizationMember{}, false
	}
	m, err := h.deps.DB.GetOrganizationMember(r.Context(), orgID, callerID)
	if err != nil {
		return model.OrganizationMember{}, false
	}
	return m, true
}

func isAdminOrOwner(role string) bool {
	return role == model.OrgMemberRoleOwner || role == model.OrgMemberRoleAdmin
}

func isOwner(role string) bool {
	return role == model.OrgMemberRoleOwner
}

func isValidRole(role string) bool {
	switch role {
	case model.OrgMemberRoleOwner, model.OrgMemberRoleAdmin,
		model.OrgMemberRoleEditor, model.OrgMemberRoleViewer:
		return true
	}
	return false
}

// --- Converters ---

func ToOrganizationResponse(o model.Organization) dto.OrganizationResponse {
	return dto.OrganizationResponse{
		ID:          o.ID.String(),
		Name:        o.Name,
		Description: o.Description,
		CreatedAt:   o.CreatedAt,
		UpdatedAt:   o.UpdatedAt,
	}
}

func ToOrganizationMemberResponse(m model.OrganizationMember) dto.OrganizationMemberResponse {
	return dto.OrganizationMemberResponse{
		UserID:         m.UserID.String(),
		OrganizationID: m.OrganizationID.String(),
		Role:           m.Role,
		CreatedAt:      m.CreatedAt,
		UpdatedAt:      m.UpdatedAt,
	}
}

// --- Organization CRUD ---

// ListOrganizations handles GET /identity/organizations
func (h *Handler) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	callerIDRaw, ok := runtime.AuthUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	callerID, err := uuid.Parse(callerIDRaw)
	if err != nil {
		http.Error(w, "Invalid caller id", http.StatusInternalServerError)
		return
	}

	orgs, err := h.deps.DB.ListOrganizations(r.Context(), callerID)
	if err != nil {
		h.deps.Log.Error("list_organizations_failed", "caller_id", callerIDRaw, "error", err)
		http.Error(w, "Failed to list organizations", http.StatusInternalServerError)
		return
	}

	out := dto.OrganizationListResponse{Organizations: make([]dto.OrganizationResponse, 0, len(orgs))}
	for _, o := range orgs {
		out.Organizations = append(out.Organizations, ToOrganizationResponse(o))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// CreateOrganization handles POST /identity/organizations
func (h *Handler) CreateOrganization(w http.ResponseWriter, r *http.Request) {
	callerIDRaw, ok := runtime.AuthUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	callerID, err := uuid.Parse(callerIDRaw)
	if err != nil {
		http.Error(w, "Invalid caller id", http.StatusInternalServerError)
		return
	}

	var req dto.OrganizationCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	orgID := uuid.New()
	org, err := h.deps.DB.CreateOrganization(r.Context(), orgID, req.Name, req.Description, callerID)
	if err != nil {
		h.deps.Log.Error("create_organization_failed", "caller_id", callerIDRaw, "error", err)
		http.Error(w, "Failed to create organization", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ToOrganizationResponse(org))
}

// GetOrganization handles GET /identity/organizations/{organization_id}
func (h *Handler) GetOrganization(w http.ResponseWriter, r *http.Request) {
	orgID, ok := parseOrgID(w, r)
	if !ok {
		return
	}

	org, err := h.deps.DB.GetOrganization(r.Context(), orgID)
	if err != nil {
		if errors.Is(err, db.ErrOrganizationNotFound) {
			http.Error(w, "Organization not found", http.StatusNotFound)
			return
		}
		h.deps.Log.Error("get_organization_failed", "org_id", orgID, "error", err)
		http.Error(w, "Failed to get organization", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ToOrganizationResponse(org))
}

// UpdateOrganization handles PATCH /identity/organizations/{organization_id}
func (h *Handler) UpdateOrganization(w http.ResponseWriter, r *http.Request) {
	orgID, ok := parseOrgID(w, r)
	if !ok {
		return
	}

	caller, ok := h.callerMembership(r, orgID)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !isAdminOrOwner(caller.Role) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req dto.OrganizationUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	org, err := h.deps.DB.UpdateOrganization(r.Context(), orgID, req.Name, req.Description)
	if err != nil {
		if errors.Is(err, db.ErrOrganizationNotFound) {
			http.Error(w, "Organization not found", http.StatusNotFound)
			return
		}
		h.deps.Log.Error("update_organization_failed", "org_id", orgID, "error", err)
		http.Error(w, "Failed to update organization", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ToOrganizationResponse(org))
}

// DeleteOrganization handles DELETE /identity/organizations/{organization_id}
func (h *Handler) DeleteOrganization(w http.ResponseWriter, r *http.Request) {
	orgID, ok := parseOrgID(w, r)
	if !ok {
		return
	}

	caller, ok := h.callerMembership(r, orgID)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !isOwner(caller.Role) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if err := h.deps.DB.DeleteOrganization(r.Context(), orgID); err != nil {
		if errors.Is(err, db.ErrOrganizationNotFound) {
			http.Error(w, "Organization not found", http.StatusNotFound)
			return
		}
		h.deps.Log.Error("delete_organization_failed", "org_id", orgID, "error", err)
		http.Error(w, "Failed to delete organization", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Membership handlers ---

// ListMembers handles GET /identity/organizations/{organization_id}/memberships
func (h *Handler) ListMembers(w http.ResponseWriter, r *http.Request) {
	orgID, ok := parseOrgID(w, r)
	if !ok {
		return
	}

	members, err := h.deps.DB.ListOrganizationMembers(r.Context(), orgID)
	if err != nil {
		h.deps.Log.Error("list_members_failed", "org_id", orgID, "error", err)
		http.Error(w, "Failed to list members", http.StatusInternalServerError)
		return
	}

	out := dto.OrganizationMemberListResponse{Members: make([]dto.OrganizationMemberResponse, 0, len(members))}
	for _, m := range members {
		out.Members = append(out.Members, ToOrganizationMemberResponse(m))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// AddMember handles POST /identity/organizations/{organization_id}/memberships
func (h *Handler) AddMember(w http.ResponseWriter, r *http.Request) {
	orgID, ok := parseOrgID(w, r)
	if !ok {
		return
	}

	caller, ok := h.callerMembership(r, orgID)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !isAdminOrOwner(caller.Role) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req dto.OrganizationMemberCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if !isValidRole(req.Role) {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}
	targetUserID, err := uuid.Parse(req.UserID)
	if err != nil {
		http.Error(w, "Invalid user_id", http.StatusBadRequest)
		return
	}

	member, err := h.deps.DB.AddOrganizationMember(r.Context(), orgID, targetUserID, req.Role)
	if err != nil {
		if errors.Is(err, db.ErrOrganizationMemberAlreadyExists) {
			http.Error(w, "User is already a member", http.StatusConflict)
			return
		}
		h.deps.Log.Error("add_member_failed", "org_id", orgID, "user_id", targetUserID, "error", err)
		http.Error(w, "Failed to add member", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ToOrganizationMemberResponse(member))
}

// GetMember handles GET /identity/organizations/{organization_id}/memberships/{user_id}
func (h *Handler) GetMember(w http.ResponseWriter, r *http.Request) {
	orgID, ok := parseOrgID(w, r)
	if !ok {
		return
	}
	targetUserID, ok := parseUserID(w, r)
	if !ok {
		return
	}

	member, err := h.deps.DB.GetOrganizationMember(r.Context(), orgID, targetUserID)
	if err != nil {
		if errors.Is(err, db.ErrOrganizationMemberNotFound) {
			http.Error(w, "Member not found", http.StatusNotFound)
			return
		}
		h.deps.Log.Error("get_member_failed", "org_id", orgID, "user_id", targetUserID, "error", err)
		http.Error(w, "Failed to get member", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ToOrganizationMemberResponse(member))
}

// UpdateMemberRole handles PATCH /identity/organizations/{organization_id}/memberships/{user_id}
func (h *Handler) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	orgID, ok := parseOrgID(w, r)
	if !ok {
		return
	}
	targetUserID, ok := parseUserID(w, r)
	if !ok {
		return
	}

	caller, ok := h.callerMembership(r, orgID)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !isAdminOrOwner(caller.Role) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req dto.OrganizationMemberUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if !isValidRole(req.Role) {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	member, err := h.deps.DB.UpdateOrganizationMemberRole(r.Context(), orgID, targetUserID, req.Role)
	if err != nil {
		if errors.Is(err, db.ErrOrganizationMemberNotFound) {
			http.Error(w, "Member not found", http.StatusNotFound)
			return
		}
		h.deps.Log.Error("update_member_role_failed", "org_id", orgID, "user_id", targetUserID, "error", err)
		http.Error(w, "Failed to update member role", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ToOrganizationMemberResponse(member))
}

// RemoveMember handles DELETE /identity/organizations/{organization_id}/memberships/{user_id}
func (h *Handler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	orgID, ok := parseOrgID(w, r)
	if !ok {
		return
	}
	targetUserID, ok := parseUserID(w, r)
	if !ok {
		return
	}

	caller, ok := h.callerMembership(r, orgID)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !isAdminOrOwner(caller.Role) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if err := h.deps.DB.RemoveOrganizationMember(r.Context(), orgID, targetUserID); err != nil {
		if errors.Is(err, db.ErrOrganizationMemberNotFound) {
			http.Error(w, "Member not found", http.StatusNotFound)
			return
		}
		h.deps.Log.Error("remove_member_failed", "org_id", orgID, "user_id", targetUserID, "error", err)
		http.Error(w, "Failed to remove member", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

func parseOrgID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := r.PathValue("organization_id")
	if raw == "" {
		http.Error(w, "Missing organization_id", http.StatusBadRequest)
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		http.Error(w, "Invalid organization_id", http.StatusBadRequest)
		return uuid.UUID{}, false
	}
	return id, true
}

func parseUserID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := r.PathValue("user_id")
	if raw == "" {
		http.Error(w, "Missing user_id", http.StatusBadRequest)
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		http.Error(w, "Invalid user_id", http.StatusBadRequest)
		return uuid.UUID{}, false
	}
	return id, true
}
