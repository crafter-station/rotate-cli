# elevenlabs adapter research

Verdict-first: **YES, full management API — but scoped to service-account keys on multi-seat workspaces.** Personal (single-user) API keys are dashboard-only.

## Auth flow

- **Base URL**: `https://api.elevenlabs.io` (also `api.us.elevenlabs.io`, `api.eu.elevenlabs.io`, `api.in.elevenlabs.io` for data-residency).
- **Auth header**: `xi-api-key: <key>`
- **Key format**: opaque token passed via `xi-api-key`. Official docs never publish a fixed prefix; examples uniformly use `ELEVENLABS_API_KEY` as a placeholder. Treat as opaque string — do NOT regex on a prefix.
- **Who can call management endpoints**: the calling `xi-api-key` must belong to a **Workspace admin** on a multi-seat plan. Service Accounts feature is gated to multi-seat customers (per `docs/overview/administration/workspaces/service-accounts`).

## Endpoints

All key-management endpoints live under `/v1/service-accounts/{service_account_user_id}/api-keys`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/service-accounts/{sa_id}/api-keys` | List keys for a service account |
| `POST` | `/v1/service-accounts/{sa_id}/api-keys` | Create a new key |
| `PATCH` | `/v1/service-accounts/{sa_id}/api-keys/{api_key_id}` | Update (rename, change permissions, limits, enable/disable) |
| `DELETE` | `/v1/service-accounts/{sa_id}/api-keys/{api_key_id}` | Delete (revoke) |

Related (not strictly rotation but needed):

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/workspace/members` or service-accounts listing | Discover `sa_id` values |
| `GET` | `/v1/user` | Sanity check current caller |

### Create request body

```json
{
  "name": "rotate-cli-managed-2026-04-20",
  "permissions": "all",                    // or array of scoped perms
  "character_limit": 1000000               // optional monthly cap
}
```

Permissions can be `"all"` or an array: `text_to_speech`, `speech_to_text`, `voices_read`, `voices_write`, `dubbing`, `workspace_read`, etc.

### Create response (200)

```json
{
  "xi-api-key": "<full new secret — only shown ONCE>",
  "key_id": "key_xxxxxxxxxxxx"
}
```

### List response (each item)

`name`, `hint` (last-4 preview), `key_id`, `service_account_user_id`, `created_at_unix`, `is_disabled`, `permissions`, `character_limit`, `character_count`, `hashed_xi_api_key`.

## metadata shape

```ts
type ElevenLabsKeyMeta = {
  provider: "elevenlabs";
  mode: "api";
  service_account_user_id: string;       // sa_...
  key_id: string;                        // key_...
  name: string;                          // rotate-cli-managed-<iso>
  permissions: string[] | "all";
  character_limit: number | null;
  hint: string;                          // last-4 from list endpoint
  created_at_unix: number;
  rotated_at: string;                    // ISO timestamp of rotation
  previous_key_id?: string;              // kept until explicit delete
};
```

## Verdict

**Fully automatable on multi-seat workspaces.** Canonical rotate flow:

1. `POST /v1/service-accounts/{sa_id}/api-keys` with new name → capture `xi-api-key` + `key_id` from response (only returned once; persist immediately).
2. Write new key to consumers (Vercel env, `.env`, secret store).
3. Verify liveness with new key: `GET /v1/user` → expect 200.
4. `DELETE /v1/service-accounts/{sa_id}/api-keys/{previous_key_id}` to revoke old key.

**Rotation semantics (important)**: old key stays valid until explicit `DELETE`. Docs confirm: "after rotating keys, you can delete the old one from this tab." This gives a clean overlap window — update consumers, verify, then delete — no downtime.

**Caveats**:
- Single-seat (personal) accounts do NOT have service accounts, so this API is unavailable. Personal keys rotate via `elevenlabs.io/app/settings/api-keys` dashboard only. Adapter should detect plan tier (via `GET /v1/user/subscription`) and fall back to manual mode if the workspace lacks service-account access.
- `sa_id` isn't in the current key's metadata — adapter must fetch it once via workspace member listing and cache in `rotate-cli` config per-workspace.
- `character_limit` is preserved on rotation only if adapter re-passes it in the Create body. Read old key's metadata first via List, copy forward.

Clean API, standard REST, no gotchas beyond the multi-seat gating.
