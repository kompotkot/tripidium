# Endpoints

## Service

Basic service endpoints used for availability checks, time diagnostics, and build/version visibility.

- `GET /ping` - **Ping pong**. Returns a simple response to confirm the API is reachable.
- `GET /health` - **Health check**. Returns the current server status.

## Authentication & Sessions

Endpoints for user authentication, token rotation, logout, and session management.

- `POST /auth/signup` - **Create account**. Registers a new user account. Args: `username`, `email`, `password`, `phone` (optional).
- `POST /auth/login` - **Sign in**. Authenticates the user and issues access and refresh tokens. Args: `email`/`username`, `password`.
- `POST /auth/refresh` - **Rotate tokens**. Validates the refresh token and issues a new token pair.
- `POST /auth/logout` - **Logout current session**. Revokes the current authenticated session.
- `GET /auth/sessions` - **List sessions**. Returns all active sessions for the current user.
- `DELETE /auth/sessions` - **Revoke all sessions**. Revokes all sessions for the current user, including the current one.
- `DELETE /auth/sessions/{session_id}` - **Revoke one session**. Revokes a specific session by its ID.

## User Profile

Endpoints for accessing and updating the current user's profile and credentials.

- `GET /user` - **Get profile**. Returns the current user's profile data. **Auth required.**
- `PATCH /user` - **Update profile**. Updates editable profile fields such as username, email, or phone. **Auth required.** Args: `username`, `email`, `phone`.
- `PUT /user/password` - **Change password**. Replaces the current password with a new one. **Auth required.** Args: `current_password`, `new_password`.

## Organizations

Endpoints for managing organizations and their members.

- `GET /organizations` - **List organizations**. Returns all organizations for the current user. **Auth required.**
- `POST /organizations` - **Create organization**. Creates a new organization. **Auth required.** Args: `name`, `description`.
- `GET /organizations/{organization_id}` - **Get organization**. Returns a specific organization by its ID. **Auth required.**
- `PATCH /organizations/{organization_id}` - **Update organization**. Updates a specific organization by its ID. **Auth required.** Args: `name`.
- `DELETE /organizations/{organization_id}` - **Delete organization**. Deletes a specific organization by its ID. **Auth required.**

Organization members management.

- `GET /organizations/{organization_id}/members` - **List organization members**. Returns all members of a specific organization by its ID. **Auth required.**
- `POST /organizations/{organization_id}/members` - **Add organization member**. Adds a new member to a specific organization by its ID, requires admin or owner role. **Auth required.** Args: `user_id`, `role`.
- `PATCH /organizations/{organization_id}/members/{user_id}` - **Update organization member role**. Updates the role of a member in a specific organization by its ID, requires admin or owner role. **Auth required.** Args: `role`.
- `DELETE /organizations/{organization_id}/members/{user_id}` - **Remove organization member**. Removes a member from a specific organization by its ID, requires admin or owner role. **Auth required.** Args: `user_id`.
