package dto

import "time"

type AuthLoginRequest struct {
	Username *string `json:"username,omitempty"`
	Email    *string `json:"email,omitempty"`
	Password string  `json:"password"`
}

type AuthLoginResponse struct {
	AccessToken string `json:"access_token"`
}

type AuthSessionResponse struct {
	ID        string    `json:"id"`
	IsCurrent bool      `json:"is_current"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UserAgent string    `json:"user_agent"`
	IP        string    `json:"ip"`
}

// SubjectUserProfile is the profile embedded in SubjectResponse when kind == "user".
type SubjectUserProfile struct {
	UserID   string  `json:"user_id"`
	Username string  `json:"username"`
	Email    string  `json:"email"`
	Phone    *string `json:"phone,omitempty"`
}

// SubjectOrganizationProfile is the profile embedded in SubjectResponse when kind == "organization".
type SubjectOrganizationProfile struct {
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name"`
}

// SubjectResponse is returned by GET /auth/subject.
// Invariant: kind == "user" => User != nil, Organization == nil.
// Invariant: kind == "organization" => Organization != nil, User == nil.
type SubjectResponse struct {
	SubjectID    string                      `json:"subject_id"`
	Kind         string                      `json:"kind"`
	IsActive     bool                        `json:"is_active"`
	User         *SubjectUserProfile         `json:"user,omitempty"`
	Organization *SubjectOrganizationProfile `json:"organization,omitempty"`
}
