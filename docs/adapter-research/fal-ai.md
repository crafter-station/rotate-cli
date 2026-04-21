# fal.ai adapter research

Research date: 2026-04-20
Target: `rotate-cli` adapter for `FAL_API_KEY` / `FAL_KEY` across 12 env vars.

## Auth flow

- **Auth scheme**: `Authorization: Key <ADMIN_API_KEY>` (note: `Key ` prefix, NOT `Bearer`).
- **Admin key required**: All `/v1/keys` management endpoints (create, list, delete) require an **ADMIN-scoped** key. Regular API keys (scope `API`) cannot call them.
- **How to get the admin key**: Dashboard-only. Created at `https://fal.ai/dashboard/keys` → "Create Key" → choose **ADMIN** scope. Docs note: "If you're not sure which to choose, start with API scope. You can always create an additional ADMIN key later if you need to deploy models." Admin key has no programmatic bootstrap — it's the root of trust and must be provisioned manually once.
- **Key format (two shapes in the wild)**:
  - Legacy compact form: `<key_id>:<key_secret>` — a single colon-joined string used as `FAL_KEY`. This is what most SDKs expect.
  - Modern form: `key_secret` starts with `fal_sk_…` (or `sk_live_…` per create-endpoint docs). Docs pages disagree slightly; both are current.
  - `key_id` is a short opaque ID (e.g. `abc123def456`).
- **Secret exposure window**: `key_secret` is returned **once** at creation. Cannot be retrieved later. If lost → delete + recreate.

## Endpoints

Base URL: `https://api.fal.ai/v1`

### POST /v1/keys — create

Request:
```bash
curl -X POST https://api.fal.ai/v1/keys \
  -H "Authorization: Key $FAL_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"alias": "rotate-cli 2026-04-20"}'
```

Body schema:
| Field | Type | Required | Notes |
|---|---|---|---|
| `alias` | string (1-255) | yes | Friendly name, used in dashboard + list |

Response (201):
```json
{
  "key_id": "abc123def456",
  "key_secret": "sk_live_…",
  "key": "abc123def456:sk_live_…"
}
```

Use `key` verbatim as the new `FAL_KEY` / `FAL_API_KEY` value.

### GET /v1/keys — list

```bash
curl "https://api.fal.ai/v1/keys?limit=50&expand=creator_info" \
  -H "Authorization: Key $FAL_ADMIN_KEY"
```

Query params: `limit`, `cursor` (pagination), `expand=creator_info`.

Response:
```json
{
  "next_cursor": "…",
  "has_more": false,
  "keys": [
    {
      "key_id": "abc123…",
      "alias": "rotate-cli 2026-04-20",
      "scope": "API",
      "created_at": "2026-04-20T…Z",
      "creator_nickname": "railly",
      "creator_email": "railly@…"
    }
  ]
}
```

Use to discover old keys by alias prefix before deletion. Scope values observed: `API`, `ADMIN`.

### DELETE /v1/keys/{key_id} — delete

```bash
curl -X DELETE https://api.fal.ai/v1/keys/abc123def456 \
  -H "Authorization: Key $FAL_ADMIN_KEY" \
  -H "Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000"
```

- Returns **204 No Content** whether key existed or not (idempotent).
- Optional `Idempotency-Key` header (UUID) for safe retries.
- Revocation is immediate; any consumer using the key loses access on the next request.

### Errors (all endpoints)
- 401 auth required, 403 access denied (wrong scope), 429 rate limit, 500 server error.

## metadata shape

For rotate-cli provider adapter output:

```ts
type FalRotationResult = {
  provider: "fal-ai";
  new_key: string;           // response.key — colon-joined, drop-in
  key_id: string;            // for later delete
  key_secret: string;        // raw secret (already embedded in new_key)
  alias: string;             // echoes request alias
  created_at: string;        // ISO8601 from subsequent list call
  old_key_ids: string[];     // ids that were deleted in this rotation
  env_vars_updated: string[];// 12 target vars (FAL_KEY, FAL_API_KEY, ...)
};
```

Recommended rotation flow:
1. List keys → find `key_id`s whose alias matches old pattern (or all `API`-scoped keys not the admin key).
2. Create new key with timestamped alias (`rotate-cli YYYY-MM-DD`).
3. Write new `key` value into all 12 env vars (Vercel/Mercury/etc).
4. Verify with a cheap probe (e.g. `GET https://api.fal.ai/v1/models/usage` with new key).
5. Delete old `key_id`s with `Idempotency-Key` set to a UUID per target.

## Dashboard-only fallback (if API unavailable)

Not needed — full API exists. But for the **bootstrap** (getting the first admin key) the dashboard is the only path:

1. Log in at `https://fal.ai/dashboard`.
2. Go to `https://fal.ai/dashboard/keys`.
3. Click "Create Key", pick **ADMIN** scope, name it (e.g. `rotate-cli-root`).
4. Copy the full `key_id:key_secret` immediately — it's shown once.
5. Store in password manager / 1Password. This is the one credential rotate-cli cannot rotate itself (chicken-and-egg). Rotate manually quarterly via same UI.

Deletions via dashboard: same page has per-row delete buttons. Useful if admin key is ever compromised — any other admin key (or account owner via dashboard) can revoke it.

## Verdict

**EASY.**

- Full REST CRUD for keys (`POST`/`GET`/`DELETE /v1/keys`).
- Clean auth header, idempotent delete, stable JSON shapes.
- Response gives drop-in `key` field — no id+secret stitching in adapter code.
- Only manual step is the one-time ADMIN key bootstrap (same as any privileged-key-rotating system — AWS root, Stripe restricted keys, etc).
- No webhooks, no async jobs, no two-step confirm. A single adapter file (~80 LOC) covers create + list + delete + verify.

Watch-outs:
- Docs disagree on prefix (`fal_sk_` vs `sk_live_`) — treat `key_secret` as opaque, always use the joined `key` field.
- Admin key is dashboard-bootstrapped → document this clearly in rotate-cli README so users don't loop forever.
- 12 env vars: make sure all are written atomically; on any write failure, DO NOT delete old keys (leave both valid, alert human).

Sources:
- https://fal.ai/docs/platform-apis/v1/keys/create
- https://fal.ai/docs/platform-apis/v1/keys/list
- https://fal.ai/docs/platform-apis/v1/keys/delete
- https://fal.ai/docs/api-reference/platform-apis/for-keys
- https://fal.ai/docs/documentation/setting-up/authentication
