# Authentication & Authorization Model

Auth uses a subject-oriented identity model. A subject is the universal authenticated or authorized principal in the system and may represent:

```text
user
organization
service_account
system_actor
external_identity
```

The JWT `sub` claim MUST contain `subject_id`. Downstream services MUST treat `sub` as an opaque immutable principal identifier and MUST NOT infer subject type from the identifier format.

Current database state:

- `subjects.id` is the universal subject identifier.
- `subjects.kind` currently allows `user` and `organization`.
- `users.id` is the user profile/account identifier and equals `subjects.id` for user subjects.
- `organizations.id` is the organization profile/resource identifier and equals `subjects.id` for organization subjects.
- Additional subject kinds such as `service_account`, `system_actor`, and `external_identity` require a schema migration before Auth can issue tokens for them.
- `auth_sessions` stores `subject_id`.

For user-password login, Auth authenticates the user, verifies the password, resolves the corresponding subject, creates an auth session, and issues an access token for the resolved subject.

Auth is responsible for authentication and subject identity. External services are responsible for authorization to resources they own. Resource membership, resource permissions, and resource-level authorization remain owned by those external services.

The regular access token MUST NOT contain the full list of resource permissions. If permissions need to be embedded into a token, they must be issued as short-lived resource-scoped tokens after checking the current authorization state in the external service that owns the resource.

## Token Model

### Identity Access Token

JWT access token is stateless and short-lived. It represents the current subject identity and does not contain the full list of resource permissions.

Default parameters from config:

- `alg` = `EdDSA` (Ed25519 signature)
- `kid` = `ed25519-v1`
- `typ` = `access+jwt`
- `iss` = `auth.tripidium`
- `aud` = `api.tripidium`
- `ttl` = `5m`

Access token identity claims:

- `sub` = subject id
- `sid` = auth session id
- `sk` = subject kind
- `iss` = configured issuer
- `aud` = configured audience
- `exp` = expiration time
- `iat` = issue time
- `jti` = token id

Recommended access token claims:

```json
{
  "sub": "subject_id",
  "sid": "auth_session_id",
  "sk": "user",
  "iss": "auth.tripidium",
  "aud": "api.tripidium",
  "typ": "access+jwt",
  "iat": 1710000000,
  "exp": 1710000300,
  "jti": "token_uuid"
}
```

Claim meaning:

- `sub` = immutable subject identifier
- `sid` = auth session identifier
- `sk` = subject kind: `user`, `organization`, `service_account`, `system_actor`, or `external_identity`

The `sk` claim is informational and may be used for routing or UX decisions. Authorization decisions must be based on explicit resource bindings, not only on `sk`.

For human login sessions, the authenticated actor is still a user. However, the authorization principal is the subject. For user-backed sessions, the token may include `user_id` as an optional actor/profile claim:

```json
{
  "sub": "subject_id",
  "user_id": "user_id",
  "sid": "auth_session_id",
  "sk": "user"
}
```

Downstream services MUST use `sub` as the principal identifier for authorization. `user_id` is a profile/account reference, not the primary authorization identity.

Generation approach:

1. Resolve the subject for the authenticated actor.
2. Build `AccessTokenClaims` with `sub`, `sid`, `sk`, and standard JWT registered claims.
3. Sign the token with the configured Ed25519 private key.
4. Set JWT header `kid` and `typ`.

Why these claim checks are required:

- `typ` protects against accepting a token of another purpose.
- `iss` protects against accepting a token from another issuer.
- `aud` protects against accepting a token minted for another service.

### Actor And Effective Subject

The model distinguishes between the authenticated subject and the effective subject:

```text
authenticated_subject:
  The subject that authenticated with Auth directly.

effective_subject:
  The subject on whose behalf the request is currently acting.
```

For a normal user request:

```text
authenticated_subject = user subject
effective_subject = user subject
```

For a user acting in an organization context:

```text
authenticated_subject = user subject
effective_subject = organization subject
```

Auth MUST verify that the authenticated subject is allowed to act as the effective subject. For organization context, this means checking organization membership and role in the organization authorization store before minting the token.

Delegated/contextual token issuance rules:

- the actor subject must be authenticated directly by Auth
- the effective subject must exist and be valid for the requested context
- the actor must have an explicit binding that allows acting as the effective subject
- the issued token must include both actor and effective subject identity
- the authorization decision and resulting token must be audit logged
- clients must not be allowed to choose an arbitrary `sub` without this server-side check

For a service account:

```text
authenticated_subject = service account subject
effective_subject = service account subject
```

Recommended JWT shape for delegated or contextual access:

```json
{
  "sub": "effective_subject_id",
  "actor_sub": "authenticated_subject_id",
  "sk": "organization",
  "actor_sk": "user",
  "sid": "auth_session_id"
}
```

Alternatively, RFC-style actor semantics may be represented as:

```json
{
  "sub": "effective_subject_id",
  "act": {
    "sub": "authenticated_subject_id",
    "sk": "user"
  }
}
```

For the initial implementation, Auth may simplify this to `sub = authenticated subject` while preserving the terminology for future organization context, service accounts, impersonation, and delegation.

### Resource-Scoped Authorization Token

Resource-scoped tokens are short-lived authorization tokens issued after checking that the subject has access to a specific external resource. They are separate from the regular identity access token.

Identity access token:

- issued by Auth after login or refresh
- represents the authenticated subject
- does not contain the full list of resource permissions
- used to call APIs that can resolve authorization from their own authorization store

Resource-scoped token:

- issued after checking the subject has access to a specific external resource
- contains resource identifier, role/scopes, and authorization version
- used for high-frequency calls to resource-owning services

Recommended resource-scoped claims:

```json
{
  "typ": "resource-access+jwt",
  "iss": "auth.tripidium",
  "aud": "api.tripidium",
  "sub": "subject_id",
  "sid": "auth_session_id",
  "resource": {
    "type": "project",
    "id": "project_id"
  },
  "role": "admin",
  "scopes": [
    "project.read",
    "db.create",
    "secret.read_meta"
  ],
  "authz_version": 42,
  "iat": 1710000000,
  "exp": 1710000600,
  "jti": "token_uuid"
}
```

Important rule:

```text
Resource permissions must not be embedded into the regular login access token as a full global permission list.
```

The source of truth for resource membership and permissions remains the external service that owns the resource.

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

## Middleware Context

Generic auth middleware should name the principal as a subject.

Middleware stores:

- `subject_id`
- `subject_kind`
- `session_id`
- `jti`
- `actor_subject_id`, optional
- `actor_subject_kind`, optional

In the delegated/contextual model:

- `subject_kind` describes the effective subject in `sub`
- `actor_subject_kind` describes the authenticated actor in `actor_sub`

Recommended context object:

```go
type AuthContext struct {
    SubjectID        uuid.UUID
    SubjectKind      string
    SessionID        uuid.UUID
    TokenID          uuid.UUID
    ActorSubjectID   *uuid.UUID
    ActorSubjectKind *string
}
```

Implementation split:

- Middleware validates JWT without database access.
- Middleware stores subject identity claims in request context.
- Handlers perform database queries when they need current subject, profile, or session state.

## Authorization Boundary

Auth is responsible for authentication and subject identity.

External services are responsible for authorization to resources they own, including projects, databases, secrets, and other resources.

Auth-issued tokens identify the subject. External authorization data determines what the subject can do.

Auth must not become the source of truth for resource membership or resource-level permissions owned by external services.

External services may trust Auth for:

- subject identity
- token signature
- issuer
- audience
- session id
- subject kind
- token expiration

External services must use their own authorization stores for:

- resource membership
- resource role
- resource ownership
- resource-level permissions
- quota-sensitive actions
- other access decisions

Conceptual authorization interface:

```text
Authorize(subject_id, action, resource) -> allow | deny
```

Examples:

```text
Authorize(subject_id, "project.read", project_id)
Authorize(subject_id, "secret.reveal", secret_id)
Authorize(subject_id, "member.invite", project_id)
```

Initially this can be implemented with simple RBAC:

```text
resource_members.role -> permissions
```

Later it can evolve into full IAM policies without changing the token identity model.

## Endpoint

### `POST /auth/login`

Login remains user-password based. The result of login must resolve the user into a subject and issue the access token for that subject.

Auth login flow:

1. Parse form data from the request.
2. Read `username`/`email`, and `password`.
3. Validate provided `username` and/or `email`, and validate `password`.
4. Load the user by `username` or `email`.
5. Verify password against `user.password_hash`.
6. Verify that the user exists and `is_active = true`.
7. Resolve the user's subject record.
8. Generate refresh token pair: raw token for cookie and SHA-256 hash for persistence.
9. Parse client metadata:
   - `created_ip` from `r.RemoteAddr` (host part if `host:port`)
   - `created_user_agent` from `r.UserAgent()` when present
10. Generate identifiers:
    - `session_id` = new UUID
    - `family_id` = new UUID
11. Compute `expires_at = now_utc + AccessSessionTTL`.
12. Create `auth_session` with:
    - `id = session_id`
    - `subject_id`
    - `family_id`
    - `refresh_token_hash`
    - `created_ip`
    - `created_user_agent`
    - `expires_at`
13. Issue access JWT for `subject_id` and `session_id`.
14. Set refresh token cookie with configured:
    - `name`
    - `path`
    - `domain`
    - `expires`
    - `HttpOnly`
    - `Secure`
    - `SameSite`
15. Return JSON response with:
    - `access_token`

Current implementation note:

- refresh token is delivered via cookie, not via JSON body
- login response body contains `access_token` only
- `auth_sessions.subject_id` identifies the subject that owns the session
- subject-backed entity tables use a shared primary key with `subjects.id`
- for user-backed subjects, `JWT sub = subjects.id = users.id`
- for organization-backed subjects, `JWT sub = subjects.id = organizations.id`

### `GET /auth/subject`

`GET /auth/subject` is the generic identity endpoint for the current subject. `GET /auth/me` is also acceptable if the API chooses that name.

Recommended flow:

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
   - `sk` is not empty
7. Return `401 Unauthorized` when JWT is invalid.
8. Extract `sub` as `subject_id`.
9. Fetch subject from the database by `subject_id`.
10. Verify that the subject exists.
11. Verify active state according to the subject kind:
    - for user-backed subjects, the user must exist and `users.is_active = true`
    - for organization-backed subjects, verify the organization exists
    - when `subjects.is_active` is added, verify it for every subject kind
12. Return `401` or `403` for missing or inactive subject according to the chosen policy.
13. Return subject identity metadata.

Safe user subject response:

```json
{
  "subject_id": "uuid",
  "kind": "user",
  "is_active": true,
  "profile": {
    "user_id": "uuid",
    "username": "ksenia",
    "email": "ksenia@example.com"
  }
}
```

Safe organization subject response:

```json
{
  "subject_id": "uuid",
  "kind": "organization",
  "is_active": true,
  "profile": {
    "organization_id": "uuid",
    "name": "Acme"
  }
}
```

Safe service account subject response:

```json
{
  "subject_id": "uuid",
  "kind": "service_account",
  "is_active": true,
  "profile": {
    "service_account_id": "uuid",
    "name": "deploy-bot"
  }
}
```

### `GET /user`

`GET /user` may remain as a convenience endpoint, but it is user-specific. It must only work when the current subject kind is `user`.

Recommended flow:

1. Validate access JWT using the same checks as `GET /auth/subject`.
2. Extract `sub` as `subject_id`.
3. Verify `sk == user`.
4. Load the user profile for the user-backed subject.
5. Verify that the user exists and `is_active = true`.
6. Return user data.

If the current subject is not a user-backed subject, return `403 Forbidden` or `404 Not Found` according to the selected policy.

### `POST /auth/refresh`

Refresh must be based on refresh token only, not on access JWT, because the access token may already be expired at refresh time. Refresh rotates sessions for the authenticated subject, not only for a user.

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
12. Load subject by `subject_id`.
13. Verify that the subject exists and is active.
14. If the subject is user-backed, verify the user also exists and `is_active = true`.
15. Return `401` or `403` according to the selected policy if the subject is missing or inactive.
16. Generate a new refresh token pair:
   - new raw refresh token for cookie
   - new refresh token hash
17. Generate new `session_id`.
18. Keep the previous `family_id`.
19. Mark the old session as rotated:
   - `revoked_at = now`
   - `revoke_reason = 'rotated'`
   - `replaced_by = new_session_id`
20. Create new `auth_session`:
   - `id = new_session_id`
   - `subject_id = old.subject_id`
   - `family_id = old.family_id`
   - `refresh_token_hash = new_hash`
   - `created_ip = current IP`
   - `created_user_agent = current User-Agent`
   - `expires_at = now + refresh/session TTL`
   - `created_at = now`
21. Issue new access JWT:
   - `sub = subject_id`
   - `sid = new_session_id`
   - `sk = subject.kind`
   - new `jti`
   - new `iat` and `exp`
22. Set refreshed cookie with configured:
   - `name`
   - `path`
   - `domain`
   - `expires`
   - `HttpOnly`
   - `Secure`
   - `SameSite`
23. Commit transaction.
24. Return JSON response with:
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
- `403 Forbidden` for inactive subject, if the API chooses to distinguish this case
- alternatively inactive subject can also be mapped to `401` to avoid leaking details

### `POST /auth/logout`

Logout should do both:

- revoke the current refresh-backed session on the server
- clear refresh cookie on the client

Why both are required:

- deleting only the cookie is not enough, because the server-side session could still remain usable
- revoking only the database row is not enough, because the browser would still keep sending the stale cookie

Auth logout flow:

1. Use `POST /auth/logout` with access-token middleware.
2. Validate current access JWT using the same access-token checks as `GET /auth/subject`.
3. Read current claims from request context:
   - `sub` as `subject_id`
   - `sid` as `auth_session.id`
4. Use `sid` as the identifier of the current `auth_session`.
5. When database state is checked, verify that the session belongs to the same subject:
   - compare `auth_sessions.subject_id` to the token `sub`
6. Revoke this session in the database:
   - `revoked_at = now`
   - `revoke_reason = 'logout'`
7. Make logout idempotent:
   - if the session is already revoked, still return success
8. Clear refresh cookie with `Set-Cookie`.
9. Use the same cookie attributes that were used during login/refresh:
   - `Name`
   - `Path`
   - `Domain`
   - `SameSite`
   - `Secure`
   - `HttpOnly`
10. Remove cookie with `Max-Age=0` or an `Expires` value in the past.
11. Return `204 No Content`.
12. Client should discard access token from memory after successful logout.

Logout must not assume that `sub` is a user ID.

Access token behavior after logout:

- access JWT is stateless, so an already issued access token may remain valid until `exp`
- this is acceptable when access-token TTL is short
- immediate access-token invalidation would require checking session state by `sid` on every request

### `GET /auth/sessions`

This endpoint returns active sessions of the current authenticated subject.

Recommended flow:

1. Use `GET /auth/sessions` with access-token middleware.
2. Validate access JWT using the standard access-token checks.
3. Read claims from request context:
   - `sub` as `subject_id`
   - `sid` as current session ID
4. Do not accept arbitrary `subject_id` from request parameters.
5. Query database only for sessions of the authenticated subject.
6. Return only sessions that are still active:
   - `revoked_at IS NULL`
   - `expires_at > now()`
7. Mark the current session with `is_current = (session.id == sid)`.
8. Return metadata-only response.

Current implementation constraint:

- session listing is supported only for user-backed subjects
- non-user subjects may receive `403 Forbidden` or a not-supported response until service-account and non-user sessions are implemented

Safe response fields:

- `id`
- `is_current`
- `created_at`
- `expires_at`
- `user_agent` in normalized form
- `ip`

Fields that must not be returned:

- `refresh_token_hash`
- raw refresh token
- `family_id`
- `replaced_by`
- revoke reasons and internal service fields
- unnecessary security metadata
