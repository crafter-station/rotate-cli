---
provider: anthropic
verdict: list-match
cost: N-calls
certainty: medium
sources:
  - "https://platform.claude.com/docs/en/api/administration-api"
  - "https://docs.anthropic.com/en/api/admin-api/organization/get-me"
  - "https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/anthropic_admin_key"
  - "https://platform.claude.com/docs/en/api/admin-api/apikeys/get-api-key"
---

# Anthropic — ownership detection

## Summary

Anthropic has the **worst** ownership story of the four providers. The introspection endpoint `GET /v1/organizations/me` exists but only accepts admin keys (`sk-ant-admin...`), not the standard `sk-ant-api03-...` keys that are actually stored in Vercel env vars. Standard inference keys have no `/me`, no org metadata in the key body, and the admin-level list endpoint `GET /v1/organizations/api_keys` returns `{id, name, status, created_at, workspace_id}` — **not the key prefix or any fragment of the secret**, so list-match has to fall back to correlating on `created_at` / `name` / `workspace_id` which is heuristic.

Verdict is `list-match` because it is the best we can do without trying to spend tokens; there is no cryptographic path.

## Strategy

Three-tier, fail-down:

### Tier 1 — admin-key-bootstrap + name/workspace correlation (preferred)

1. Each Anthropic admin Hunter has master access to gets its own `sk-ant-admin...` cached in rotate-cli's keychain.
2. On `rotate login anthropic`, rotate-cli calls `GET /v1/organizations/me` to learn the org id and caches it.
3. For each admin, rotate-cli also calls `GET /v1/organizations/api_keys?limit=1000&status=active` and stores the list of `{id, name, workspace_id, created_at, partial_key_hint?}`.
   - As of 2026-04, Anthropic does not expose a `partial_key` or `last_four` on this endpoint. Verify on-live when implementing; if present, use it.
4. When inspecting a Vercel env var holding `sk-ant-api03-...`:
   - Call `POST /v1/messages` with `max_tokens: 1` and a trivial prompt using that key. If the response includes any header like `anthropic-organization-id` (currently undocumented — verify), read it.
   - Otherwise, route to Tier 2.

### Tier 2 — create-probe (destructive, use sparingly)

Any write using `sk-ant-api03-...` is billable, but a `max_tokens: 1` `POST /v1/messages` costs ~$0.0001 on Haiku and confirms the key works. Response headers currently return rate-limit state scoped to the calling org (e.g. `anthropic-ratelimit-tokens-limit`), but **no public header exposes the `organization_id`**. Tier 2 therefore only tells us "valid" vs "revoked", not owner. Use only to filter out dead keys before Tier 3.

### Tier 3 — fingerprint the Vercel metadata context

When the Anthropic API cannot distinguish ownership, fall back to the Vercel env var metadata that rotate-cli already has: project id, env var name, and the sibling env vars. If `ANTHROPIC_API_KEY` lives in a project whose `CLERK_SECRET_KEY` or `OPENAI_API_KEY` resolved to "self" in their own adapters, treat the Anthropic key as "self" by association. This is explicitly heuristic and should be surfaced to the user with a "inferred from sibling env vars" warning.

## Endpoints used

```bash
# Tier 1a — admin org id (requires sk-ant-admin...)
curl https://api.anthropic.com/v1/organizations/me \
  -H "x-api-key: $ANTHROPIC_ADMIN_KEY" \
  -H "anthropic-version: 2023-06-01"

# 200 response:
{
  "id": "12345678-1234-5678-1234-567812345678",
  "type": "organization",
  "name": "Clerk"
}

# Tier 1b — list API keys for an org (requires sk-ant-admin...)
curl "https://api.anthropic.com/v1/organizations/api_keys?limit=1000&status=active" \
  -H "x-api-key: $ANTHROPIC_ADMIN_KEY" \
  -H "anthropic-version: 2023-06-01"

# Response shape (per admin API docs):
{
  "data": [
    {
      "id": "apikey_01ABC...",
      "name": "production",
      "status": "active",
      "workspace_id": "wrkspc_01XYZ...",
      "created_at": "2025-11-03T...",
      "created_by": { "id": "user_01...", "type": "user" }
    }
  ],
  "has_more": false
}
# Does NOT include key_prefix or last_four. We cannot match a raw sk-ant-api03-
# string against any field in this response.

# Tier 2 — liveness probe (small cost, api03 key)
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $SUSPECT_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-3-5-haiku-latest","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}'
# Use the response status to confirm the key is live. No org_id is returned.
```

## Implementation hints

```ts
// adapter-anthropic/ownership.ts

type Ctx = {
  admins: Array<{
    orgId: string;
    orgName: string;
    adminKey: string;           // encrypted at rest
    keyList: Array<{            // fetched on bootstrap + refreshed on rotate
      id: string;
      name: string;
      workspaceId: string;
      createdAt: string;
    }>;
  }>;
  // Sibling signal fallback.
  vercelSiblingOwnership?: 'self' | 'other' | 'unknown';
};

export async function ownedBy(
  secret: string,
  ctx: Ctx,
  vercelEnvMeta: { projectId: string; envVarName: string; createdAt: string },
): Promise<'self' | 'other' | 'unknown'> {
  // Tier 2 — confirm it's alive at all.
  const alive = await ping(secret);
  if (!alive) return 'unknown';

  // Tier 1 — correlate by vercel metadata against each admin's keyList.
  // Anthropic API keys have a `created_at` field; Vercel env vars have the
  // timestamp when the secret was last updated. If a Vercel env var was last
  // updated within a minute of an Anthropic api_keys entry's `created_at`,
  // and the Vercel env var name matches the Anthropic key's `name`
  // (engineers often reuse names), treat that as a probable match.
  for (const admin of ctx.admins) {
    const matches = admin.keyList.filter(k =>
      looselyMatches(k.name, vercelEnvMeta.envVarName) ||
      closeInTime(k.createdAt, vercelEnvMeta.createdAt, 2 * 60 * 1000),
    );
    if (matches.length > 0) return 'self';
  }

  // Tier 3 — fall back to sibling env-var ownership.
  if (ctx.vercelSiblingOwnership === 'self') return 'self';
  if (ctx.vercelSiblingOwnership === 'other') return 'other';

  return 'unknown';
}

async function ping(key: string): Promise<boolean> {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: 'claude-3-5-haiku-latest',
      max_tokens: 1,
      messages: [{ role: 'user', content: 'ping' }],
    }),
  });
  return res.status < 500 && res.status !== 401;
}
```

## Edge cases

- **No admin key held**: rotate-cli cannot start Tier 1. Must either require the user to supply one, or degrade gracefully to Tier 3 (sibling inference) + explicit confirmation. Document this loudly — Anthropic ownership is the weakest link.
- **Admin key revoked while a rotation is mid-flight**: Tier 1 calls fail; degrade to Tier 3 and block revocation of the old key until a human confirms.
- **Name collision ("production" in two orgs)**: name-matching is guaranteed to collide. Pair with `createdAt` proximity, and if both admins have a key named "production" created within the same 2-minute window, surface an ambiguity prompt.
- **Legacy `sk-ant-api-...` keys (pre-api03)**: same story — no introspection. Treat identically.
- **OAuth-subject keys (`sk-ant-oat01-...`)**: tied to a Claude.ai subscription user, not an API org; these should never appear in Vercel env vars normally. If detected, flag as misconfiguration.
- **Workspace-scoped admin keys**: the `api_keys` list is workspace-filterable. If Hunter's admin key is workspace-scoped, he only sees that workspace's keys. A key created in a sibling workspace of the same org will not appear → falsely reported `other`. Mitigate by keeping one org-wide admin key for rotate-cli at bootstrap.
- **Rate limits**: Anthropic admin API is rate-limited separately from inference; document the 429 and back off.
- **Headers leak org_id (future)**: if Anthropic ever exposes `anthropic-organization-id` on inference responses (reasonable ask — it would match OpenAI parity), this upgrades from `list-match` to `api-introspection` instantly. Worth filing a feature request to their DX team; this research should be re-run quarterly.
