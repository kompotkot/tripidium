# Endpoints

## Service

Basic service endpoints used for availability checks, time diagnostics, and build/version visibility.

- `GET /ping` - **Ping pong**. Returns a simple response to confirm the API is reachable.
- `GET /health` - **Health check**. Returns the current server status.

## Authentication & Sessions

Endpoints for user authentication, token rotation, logout, and session management.

- `POST /auth/signup` - **Create account**. Registers a new user account.
- `POST /auth/login` - **Sign in**. Authenticates the user and issues access and refresh tokens.
- `POST /auth/refresh` - **Rotate tokens**. Validates the refresh token and issues a new token pair.
- `POST /auth/logout` - **Logout current session**. Revokes the current authenticated session.
- `GET /auth/sessions` - **List sessions**. Returns all active sessions for the current user.
- `DELETE /auth/sessions` - **Revoke all sessions**. Revokes all sessions for the current user, including the current one.
- `DELETE /auth/sessions/{session_id}` - **Revoke one session**. Revokes a specific session by its ID.

## User Profile

Endpoints for accessing and updating the current user's profile and credentials.

- `GET /user` - **Get profile**. Returns the current user's profile data.
- `PATCH /user` - **Update profile**. Updates editable profile fields such as username, email, or phone.
- `PUT /user/password` - **Change password**. Replaces the current password with a new one.
