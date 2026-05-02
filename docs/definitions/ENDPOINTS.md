# Endpoints

Fixed agreement:

1. `/auth` is not identity CRUD.
2. `/auth` handles login, token issuance, refresh, logout, sessions.
3. User registration is `/identity/users`, not just `/auth/signup`.
4. Organizations are `/identity/organizations`.
5. Organization membership is a first-class resource: `/memberships`.
6. Service accounts are managed identities: `/identity/.../service-accounts`.
7. Machine tokens are issued through `/auth/token` with `client_credentials`, not `login/signup`.
8. JWT sub is always `subject_id`.
9. Typed IDs exist only inside typed resources: `user.id`, `organization.id`, `service_account.id`.
10. Authorization later grows into `/iam` `bindings/policies`.

## Service

Basic service endpoints used for availability checks, time diagnostics, and build/version visibility.

- `GET /ping` - **Ping pong**. Returns a simple response to confirm the API is reachable.
- `GET /health` - **Health check**. Returns the current server status.

## Authentication & Sessions

Endpoints for user authentication, token rotation, logout, and session management.

- `POST /auth/login` - **Authenticate user**. Authenticates a user and creates a user-backed auth session. Args: `username` or `email`, `password`.
- `POST /auth/refresh` - **Rotate refresh token**. Validates the refresh token and issues a new access token and refresh token.
- `POST /auth/logout` - **Logout current session**. Revokes the current session and clears the refresh cookie.
- `GET /auth/sessions` - **List sessions**. Returns active sessions for the current authenticated subject.
- `DELETE /auth/sessions` - **Revoke all sessions**. Revokes all sessions for the current authenticated subject, including the current session, and clears the refresh cookie.
- `DELETE /auth/sessions/{session_id}` - **Revoke one session**. Revokes one session for the current authenticated subject.
- `GET /auth/subject` - **Get current subject**. Returns the current authenticated subject identity and typed profile.
- `POST /auth/token` - **Issue token**. Issues a token using a supported grant type. Args: `grant_type`, client credentials depending on grant type. _Not implemented until service account credentials are introduced._

## Identity / Users

Endpoints for managing user accounts and the current user's profile and credentials.

- `POST /identity/users` - **Register user**. Creates a new user-backed subject. Args: `username`, `email`, `password`, `phone` optional.
- `GET /identity/users/current` - **Get current user profile**. Returns the user profile for the current user-backed subject.
- `PATCH /identity/users/current` - **Update current user profile**. Updates editable user profile fields. Args: `username` optional, `email` optional, `phone` optional.
- `PUT /identity/users/current/password` - **Change current user password**. Changes password for the current user-backed subject.

## Identity / Organizations

Endpoints for managing organization subjects.

- `GET /identity/organizations` - **List organizations**. Returns organizations where the current user-backed subject is a member.
- `POST /identity/organizations` - **Create organization**. Creates an organization subject and assigns the current user as owner. Args: `name`, `description` optional.
- `GET /identity/organizations/{organization_id}` - **Get organization**. Returns organization details.
- `PATCH /identity/organizations/{organization_id}` - **Update organization**. Updates editable organization fields. Requires organization admin or owner. Args: `name` optional, `description` optional.
- `DELETE /identity/organizations/{organization_id}` - **Delete organization**. Requires organization owner.

## Identity / Organization Memberships

Endpoints for managing organization member records.

- `GET /identity/organizations/{organization_id}/memberships` - **List organization memberships**. Returns all membership records for the organization.
- `POST /identity/organizations/{organization_id}/memberships` - **Add organization member**. Adds a user to the organization with the specified role. Args: `user_id`, `role`.
- `GET /identity/organizations/{organization_id}/memberships/{user_id}` - **Get user membership**. Returns membership details for the specified user in the organization.
- `PATCH /identity/organizations/{organization_id}/memberships/{user_id}` - **Update membership role**. Updates the role for the specified user in the organization. Args: `role`.
- `DELETE /identity/organizations/{organization_id}/memberships/{user_id}` - **Remove organization member**. Removes the specified user from the organization. Requires organization admin or owner.
