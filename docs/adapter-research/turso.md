---
type: note
created: 2026-04-20
provider: turso
vars_in_scope: 8
rotation_verdict: api-supported
cli_piggyback: true
---

# Turso — Secret Rotation Research

**Target env vars (8):** `TURSO_AUTH_TOKEN`, `TURSO_DATABASE_URL`, plus per-environment variants (dev/staging/prod × auth-token/database-url).

## Verdict

**API-supported, end-to-end.** Turso has a first-class Platform API for rotating both DB auth tokens and platform API tokens. The `turso` CLI wraps these, so rotate-cli can piggyback on the CLI or hit the API directly.

`TURSO_DATABASE_URL` is stable (libsql://{db}-{org}.turso.io) — only rotates if DB is renamed. `TURSO_AUTH_TOKEN` is the hot one.

## Auth (how we get the master token)

Rotate-cli needs a **Platform API token** (not a DB token) to perform rotations. Two ways:

1. `turso auth api-tokens mint rotate-cli --org {slug}` → prints JWT once.
2. `POST https://api.turso.tech/v1/auth/api-tokens/{tokenName}` with Bearer of an existing platform token.

Store in `rotate-cli` vault as `TURSO_PLATFORM_TOKEN`. Scope to a single org with `--org` for blast-radius containment. Token is shown once, JWT format.

## Endpoints

Base: `https://api.turso.tech`

### Rotate all DB auth tokens (the primary operation)
```
POST /v1/organizations/{org}/databases/{db}/auth/rotate
Authorization: Bearer {TURSO_PLATFORM_TOKEN}
```
- Invalidates **all** outstanding auth tokens for that DB.
- Brief downtime during rotation (docs say "brief").
- 200 empty body on success, 404 if DB missing.
- Node SDK equivalent: `turso.databases.rotateTokens(dbName)`.

### Mint a new DB auth token (fresh TURSO_AUTH_TOKEN)
```
POST /v1/organizations/{org}/databases/{db}/auth/tokens
  ?expiration=never          # or "2w1d30m"
  &authorization=full-access # or read-only
Authorization: Bearer {TURSO_PLATFORM_TOKEN}
```
Response: `{ "jwt": "eyJ..." }` — this is the new `TURSO_AUTH_TOKEN`.
Optional body: `{ "permissions": { "read_attach": { "databases": [...] } } }`.

### Platform API token lifecycle
```
POST   /v1/auth/api-tokens/{tokenName}     # mint (org scope in body)
GET    /v1/auth/api-tokens                 # list
DELETE /v1/auth/api-tokens/{tokenName}     # revoke
```

## Recommended rotation flow for rotate-cli

```
1. Mint new DB auth token:
     POST /v1/organizations/{org}/databases/{db}/auth/tokens
   → returns { jwt } = NEW_TURSO_AUTH_TOKEN

2. Write NEW_TURSO_AUTH_TOKEN to all target destinations
   (Vercel, Doppler, .env.prod, etc.) before invalidating.

3. Redeploy / let consumers pick up new token.

4. Invalidate old tokens:
     POST /v1/organizations/{org}/databases/{db}/auth/rotate
   → kills everything, including the old token plus (important) the new one too if minted before rotate.

   ⚠️ ORDER MATTERS: mint AFTER rotate, or mint-rotate-mint.

Safer flow:
1. POST /auth/rotate           # nuke all
2. POST /auth/tokens            # mint fresh
3. Deploy new token everywhere
4. Accept ~seconds of 401s during step 3 (brief downtime)
```

## CLI piggyback (preferred for MVP)

`turso` CLI exposes:
```bash
turso db tokens create <db> [--expiration 7d] [--read-only]   # mint
turso db tokens invalidate <db>                               # rotate-all (equivalent to /auth/rotate)
turso auth api-tokens mint <name> [--org <slug>]              # platform token mint
turso auth api-tokens list
turso auth api-tokens revoke <name>
```

Rotate-cli can shell out to `turso` (zero HTTP plumbing) if `turso` binary is present. Detect with `which turso`. Fall back to HTTP API otherwise.

## Metadata rotate-cli should store

Per-env (dev/staging/prod):
- `organizationSlug`
- `databaseName`
- `TURSO_PLATFORM_TOKEN` (for rotation auth, kept in rotate-cli vault)
- `expirationPolicy` (default: `never` for service, `7d` for dev/CI)
- `authorization` (`full-access` vs `read-only`)

## Gotchas

- `/auth/rotate` invalidates **everything**, including tokens minted seconds before. Always mint-after-rotate.
- Brief connection churn during rotate — not zero-downtime without a read-replica warmup.
- Platform token scoped to org can't touch other orgs (good for blast-radius).
- Token shown once — rotate-cli must capture + write atomically.

## Sources
- [Turso Platform API intro](https://docs.turso.tech/api-reference/introduction)
- [Create DB token](https://docs.turso.tech/api-reference/databases/create-token) — `POST /databases/{db}/auth/tokens`
- [Invalidate DB tokens](https://docs.turso.tech/api-reference/databases/invalidate-tokens) — `POST /databases/{db}/auth/rotate`
- [CLI auth api-tokens](https://docs.turso.tech/cli/auth/api-tokens)
- [CLI db tokens](https://docs.turso.tech/cli/db/tokens)
