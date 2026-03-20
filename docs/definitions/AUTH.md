# Auth

### Access Token

JWT access token must be stateless and short-lived (recommended TTL: 5-15 minutes).

Head:

- `alg` — `EdDSA` (Ed25519) algorithm
- `kid` — key ID
- `typ` — for ex. access+jwt

Payload:

- `sub` — `user_id`
- `sid` — `auth_session.id`
- `iss` — who issued the token (for ex. `auth.myapp`)
- `aud` — for whom (for ex. `api.myapp`)
- `exp` — short live TTL (for ex. 5-15 minutes)
- `iat` — issue time
- `jti` — unique ID of exact access token

### Refresh Token

Opaque random token (32 bytes from `crypto/rand`, base64url encoded), linked to `auth_session` and stored as hash id database.

## Endpoints

### `POST /auth/login`

1. Validate credentials.
2. Generate 32 bytes from `crypto/rand` for refresh token, hash token before persistence.
3. Create identifiers:
   - `session_id` (unique session)
   - `family_id` (token-rotation family)
4. Store in `auth_session` record:
   - `id` = `session_id`
   - `user_id`
   - `family_id`
   - `refresh_token_hash`
   - `created_ip`
   - `created_user_agent`
   - `created_at`
   - `expires_at`
5. Issue access JWT (signed with private key referenced by `kid`):
   - `sub` = `user_id`
   - `sid` = `session_id`
   - `iss`, `aud`
   - `iat`, `exp`
   - `jti`
6. Respond with:
   - `access_token` (JWT)
   - `refresh_token` (opaque token, returned only once)
