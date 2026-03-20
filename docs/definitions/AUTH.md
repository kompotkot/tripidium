# Auth

### Access Token

Based on JWT short live TTL 5-15 minutes stateless.

Head:

- `alg` — жестко зафиксированный алгоритм
- `kid` — key ID
- `typ` — for ex. access+jwt

Payload:

- `iss` — who issued the token (for ex. `auth.myapp`)
- `aud` — for whom (for ex. `api.myapp`)
- `sub` — `user_id`
- `sid` — `auth_session.id`
- `exp` — short live TTL (for ex. 10–5 minutes)
- `iat` — issue time
- `jti` — unique ID of exact access token

### Refresh Token

Linked to `auth_session` table and 32 bytes from `crypto/rand`
