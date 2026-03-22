# Auth

## Token Model

### Access Token

JWT access token is stateless and short-lived.

Default parameters from config:

- `alg` = `EdDSA` (Ed25519 signature)
- `kid` = `ed25519-v1`
- `typ` = `access+jwt`
- `iss` = `auth.tripidium`
- `aud` = `api.tripidium`
- `ttl` = `5m`

Access token claims:

- `sub` = `user_id`
- `sid` = `auth_session.id`
- `iss` = configured issuer
- `aud` = configured audience
- `exp` = `iat + AccessTokenTTL`
- `iat` = issue time in UTC
- `jti` = random UUID of this exact token

Generation approach:

1. Build `AccessTokenClaims` with `sid` plus standard JWT registered claims.
2. Sign the token with the configured Ed25519 private key.
3. Set JWT header `kid` and `typ`.

### Refresh Token

Refresh token is opaque and stateful.

Default parameters from config:

- raw entropy length = `32` bytes
- session TTL = `7d`

Generation approach:

1. Generate `RefreshTokenLen` random bytes using `crypto/rand`.
2. Encode raw bytes with base64url without padding.
3. Compute SHA-256 from the encoded token.
4. Store only the hash in the database.
5. Return the raw refresh token to the client once.

## Endpoint

### `POST /auth/login`

Auth login flow:

1. Parse form data from the request.
2. Read `username`/`email`, and `password`.
3. Validate provided `username` and/or `email`, and validate `password`.
4. Load the user by `username` or `email`.
5. Verify password against `user.password_hash`.
6. Generate refresh token pair: raw token for cookie and SHA-256 hash for persistence.
7. Parse client metadata:
   - `created_ip` from `r.RemoteAddr` (host part if `host:port`)
   - `created_user_agent` from `r.UserAgent()` when present
8. Generate identifiers:
   - `session_id` = new UUID
   - `family_id` = new UUID
9. Compute `expires_at = now_utc + AccessSessionTTL`.
10. Create `auth_session` with:
    - `id = session_id`
    - `user_id`
    - `family_id`
    - `refresh_token_hash`
    - `created_ip`
    - `created_user_agent`
    - `expires_at`
11. Issue access JWT for `user_id` and `session_id`.
12. Set refresh token cookie with configured:
    - `name`
    - `path`
    - `domain`
    - `expires`
    - `HttpOnly`
    - `Secure`
    - `SameSite`
13. Return JSON response with:
    - `access_token`

Current implementation note:

- refresh token is delivered via cookie, not via JSON body
- login response body contains `access_token` only

### `GET /user`

Get user flow:

1. Parse `Authorization` header with `Bearer` token.
2. Reject empty or malformed `Authorization` header.
3. Parse JWT and allow only the expected signing algorithm `EdDSA`.
4. Use `kid` from JWT header to select a public key only from the trusted local key set.
5. Verify JWT signature with the selected public key.
6. Validate claims:
   - `typ == access+jwt`
   - `iss == auth.tripidium`
   - `aud == api.tripidium`
   - `exp > now`
   - `sub` is not empty
   - `sid` is not empty
7. Return `401 Unauthorized` when JWT is invalid.
8. Extract `sub` as `user_id`.
9. Fetch user from the database by `user_id`.
10. Verify that the user exists and `is_active = true`.
11. Return `401` or `403` for missing or inactive user according to the chosen policy.
12. Return user data.

Implementation split:

- Middleware validates JWT without database access.
- Middleware stores `user_id`, `session_id`, and `jti` in request context.
- `GET /user` handler performs one database query to load the user.

Why these claim checks are required:

- `typ` protects against accepting a token of another purpose.
- `iss` protects against accepting a token from another issuer.
- `aud` protects against accepting a token minted for another service.

### `POST /auth/refresh`

Refresh must be based on refresh token only, not on access JWT, because the access token may already be expired at refresh time.

Preferred transport:

- read refresh token from `HttpOnly` cookie
- use `Secure` in production
- set explicit `SameSite` policy

Auth refresh flow:

1. Read refresh token from request, preferably from `HttpOnly` cookie.
2. Do not require access token for this endpoint.
3. Validate refresh token format:
   - token is not empty
   - token has expected length
   - token is valid base64url if that is the chosen encoding
4. Compute `refresh_token_hash = SHA-256(raw_refresh_token)`.
5. Open database transaction.
6. Find `auth_session` by `refresh_token_hash` and lock the row with `FOR UPDATE`.
7. Return `401 Unauthorized` if session is not found.
8. Check whether the session is already revoked.
9. If `revoked_at IS NOT NULL`, treat the token as invalid:
   - this may indicate refresh token reuse after rotation
   - revoke the whole token family by `family_id`
   - return `401 Unauthorized`
10. If `expires_at <= now()`, return `401 Unauthorized`.
11. Optionally mark expired session as revoked with reason `expired`.
12. Load user by `user_id`.
13. Verify that the user exists and `is_active = true`.
14. Return `401` or `403` according to the selected policy if the user is missing or inactive.
15. Generate a new refresh token pair:
   - new raw refresh token for cookie
   - new refresh token hash
16. Generate new `session_id`.
17. Keep the previous `family_id`.
18. Mark the old session as rotated:
   - `revoked_at = now`
   - `revoke_reason = 'rotated'`
   - `replaced_by = new_session_id`
19. Create new `auth_session`:
   - `id = new_session_id`
   - `user_id = old.user_id`
   - `family_id = old.family_id`
   - `refresh_token_hash = new_hash`
   - `created_ip = current IP`
   - `created_user_agent = current User-Agent`
   - `expires_at = now + refresh/session TTL`
   - `created_at = now`
20. Issue new access JWT:
   - `sub = user_id`
   - `sid = new_session_id`
   - new `jti`
   - new `iat` and `exp`
21. Set refreshed cookie with configured:
   - `name`
   - `path`
   - `domain`
   - `expires`
   - `HttpOnly`
   - `Secure`
   - `SameSite`
22. Commit transaction.
23. Return JSON response with:
   - `access_token`

Refresh rotation rules:

- every successful refresh must issue a new refresh token
- previous refresh token must be invalidated
- token lineage must be preserved through `family_id` and `replaced_by`
- refreshed raw token should be returned via cookie, not via JSON body

Reuse detection:

- if a presented refresh token is found but already revoked, and it belongs to a rotated chain, treat the whole `family_id` as compromised
- revoke all active sessions in the same family
- return `401 Unauthorized`
- require full login again

Minimal status policy:

- `401 Unauthorized` for token not found, expired, revoked, or reuse detected
- `403 Forbidden` for inactive user, if the API chooses to distinguish this case
- alternatively inactive user can also be mapped to `401` to avoid leaking details

### `POST /auth/logout`

Logout should do both:

- revoke the current refresh-backed session on the server
- clear refresh cookie on the client

Why both are required:

- deleting only the cookie is not enough, because the server-side session could still remain usable
- revoking only the database row is not enough, because the browser would still keep sending the stale cookie

Auth logout flow:

1. User `POST /auth/logout` with access-token middleware.
2. Validate current access JWT using the same access-token checks as `GET /user`.
3. Read current claims from request context:
   - `sub`
   - `sid`
4. Use `sid` as the identifier of the current `auth_session`.
5. Revoke this session in the database:
   - `revoked_at = now`
   - `revoke_reason = 'logout'`
6. Make logout idempotent:
   - if the session is already revoked, still return success
7. Clear refresh cookie with `Set-Cookie`.
8. Use the same cookie attributes that were used during login/refresh:
   - `Name`
   - `Path`
   - `Domain`
   - `SameSite`
   - `Secure`
   - `HttpOnly`
9. Remove cookie with `Max-Age=0` or an `Expires` value in the past.
10. Return `204 No Content`.
11. Client should discard access token from memory after successful logout.

Access token behavior after logout:

- access JWT is stateless, so an already issued access token may remain valid until `exp`
- this is acceptable when access-token TTL is short
- immediate access-token invalidation would require checking session state by `sid` on every request
