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
6. Generate refresh token pair: raw token for response and SHA-256 hash for persistence.
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
12. Return JSON response with:
    - `access_token`
    - `refresh_token`
