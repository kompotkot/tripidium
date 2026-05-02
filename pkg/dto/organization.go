package dto

import "time"

type OrganizationCreateRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

type OrganizationUpdateRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

type OrganizationResponse struct {
	Id          string    `json:"id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type OrganizationMemberCreateRequest struct {
	UserId string `json:"user_id"`
	Role   string `json:"role"`
}

type OrganizationMemberUpdateRequest struct {
	Role string `json:"role"`
}

type OrganizationMemberDeleteRequest struct {
	UserId string `json:"user_id"`
}

type OrganizationMemberResponse struct {
	UserId         string    `json:"user_id"`
	OrganizationId string    `json:"organization_id"`
	Role           string    `json:"role"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type OrganizationMemberListResponse struct {
	Members []OrganizationMemberResponse `json:"members"`
}
