---
provider: polar
verdict: list-match
cost: 1-call (OAT) | 0-calls (webhook-secret)
certainty: high (OAT) | low (webhook-secret)
sources:
  - "https://polar.sh/docs/api-reference/organization-access-tokens/list"
  - "https://github.com/polarsource/polar/blob/main/server/polar/organization_access_token/schemas.py"
  - "https://github.com/polarsource/polar/blob/main/server/polar/organization_access_token/service.py"
  - "https://polar.sh/docs/api-reference/webhooks/endpoints"
  - "https://api.polar.sh/openapi.json"
---

# Polar — ownership detection

Target env vars: `POLAR_ACCESS_TOKEN` (OAT, `polar_oat_*`) and `POLAR_WEBHOOK_SECRET` (`polar_whs_*`).

Two distinct credentials, handled differently. The OAT case is trivial and high-certainty; the webhook secret is the adversarial case because it does not bind to any identifier the bearer can query.

## Strategy

### A. `POLAR_ACCESS_TOKEN` (OAT) — list-match via admin bootstrap OAT

An OAT does not carry embedded org info in its plaintext (`polar_oat_<52+ opaque chars>`), so **format-decode is impossible**. But the resource it represents — `OrganizationAccessToken` — has `organization_id` in its read schema. Since the admin already holds a bootstrap OAT with `organization_access_tokens:read` scope, one `GET /v1/organization-access-tokens/` per org returns every OAT in that org along with `{ id, organization_id, comment, last_used_at, scopes, expires_at }`.

The bearer we're inspecting is the plaintext; the list returns `id` (UUID) and a `hashed_xi_api_key`-style hint only internally. We cannot match plaintext to a list entry directly. Instead:

1. **Probe the candidate** by calling any cheap authenticated endpoint with the secret under test. Use `GET /v1/organizations/` (requires no special scope — even minimal OATs read their own org). Response returns exactly one `Organization` whose `id` is the OAT's owning org.
2. Compare that `organization_id` against `ctx.knownOrgIds` (seeded from the bootstrap OAT's `GET /v1/organizations/`).
3. Hit → `self`. Miss → `other`. Error/401 → `unknown`.

This is technically closer to `api-introspection` than `list-match`, but there is no `/me` primitive — the org list returned by `GET /v1/organizations/` **is** the introspection, since an OAT is organization-scoped and that endpoint reflects its scope. One call, authoritative.

### B. `POLAR_WEBHOOK_SECRET` — format-decode fails, list-match requires N calls

`polar_whs_*` is **not** a bearer. It cannot be used in `Authorization:`. It's only an HMAC signing key for `WebhookEndpoint.secret`. There is no endpoint that accepts it, so introspection is impossible.

Fallback: hash-index against admin's webhook endpoints.

1. Bootstrap OAT calls `GET /v1/webhooks/endpoints?organization_id={org}` for every known org → returns `WebhookEndpoint[]` including `{ id, url, secret, events, format, organization_id }`.
2. The endpoint response includes `secret` in plaintext for endpoints the caller owns (verified via `WebhookEndpoint` schema in openapi.json — `secret` is not redacted when the caller has `webhooks:read`).
3. Build `Map<secret_plaintext, organization_id>`; then `Map.get(candidate)` is O(1).

Certainty is **low** because:
- Secret may have been rotated out-of-band since the map was built.
- Secret may belong to a webhook the bootstrap OAT cannot read (different org).
- `secret` might be redacted in future Polar versions (it's loadable today, 2026-04-20).

## Endpoints used

Base: `https://api.polar.sh/v1` (sandbox: `https://sandbox-api.polar.sh/v1`).

```
# OAT introspection — 1 call, high certainty
GET /v1/organizations/
Authorization: Bearer <candidate polar_oat_*>

# 200 -> { items: [{ id: "org_uuid", name, slug, ... }], pagination }
# OATs are single-org scoped, so items[0].id is THE owning org.
```

```
# Webhook secret index — N calls at setup, 0 at query time
GET /v1/webhooks/endpoints?organization_id={org}&page=1&limit=100
Authorization: Bearer <bootstrap OAT with webhooks:read>

# 200 -> { items: [{ id, organization_id, secret: "polar_whs_...", ... }] }
```

```
# Admin bootstrap — seed known orgs
GET /v1/organizations/
Authorization: Bearer <bootstrap OAT>
```

Auth scheme: `Authorization: Bearer polar_oat_...`. OATs share the header format with OAuth2 access tokens (`polar_at_u_*`, `polar_at_o_*`) and PATs, but OATs are what live in rotate-cli's target env vars.

## Implementation hints (pseudocode)

```ts
// adapter-polar/ownership.ts

type Ctx = {
  knownOrgIds: Set<string>;               // seeded from bootstrap OAT -> GET /v1/organizations
  webhookSecretIndex?: Map<string, string>; // plaintext polar_whs_* -> organization_id
  bootstrapOat: string;                    // polar_oat_* with organization_access_tokens:read + webhooks:read
};

type OrgListResp = { items: Array<{ id: string; name: string; slug: string }> };

export async function ownedBy(
  secret: string,
  ctx: Ctx,
): Promise<"self" | "other" | "unknown"> {
  // Tier 1: webhook secret — can never be a bearer
  if (secret.startsWith("polar_whs_")) {
    const idx = ctx.webhookSecretIndex ?? await buildWebhookIndex(ctx);
    const orgId = idx.get(secret);
    if (orgId && ctx.knownOrgIds.has(orgId)) return "self";
    if (orgId) return "other";
    return "unknown"; // not in admin's visible endpoints
  }

  // Tier 2: OAT (or OAuth2 token) — probe via /v1/organizations
  if (/^polar_(oat|at_[uo]|pat)_/.test(secret)) {
    const res = await fetch("https://api.polar.sh/v1/organizations/", {
      headers: { Authorization: `Bearer ${secret}` },
    });
    if (res.status === 401 || res.status === 403) return "unknown";
    if (!res.ok) return "unknown";
    const body = (await res.json()) as OrgListResp;
    const ids = body.items.map(o => o.id);
    if (ids.some(id => ctx.knownOrgIds.has(id))) return "self";
    if (ids.length > 0) return "other";
    return "unknown";
  }

  return "unknown";
}

async function buildWebhookIndex(ctx: Ctx): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  for (const orgId of ctx.knownOrgIds) {
    const res = await fetch(
      `https://api.polar.sh/v1/webhooks/endpoints?organization_id=${orgId}&limit=100`,
      { headers: { Authorization: `Bearer ${ctx.bootstrapOat}` } },
    );
    if (!res.ok) continue;
    const body = await res.json();
    for (const wh of body.items ?? []) {
      if (typeof wh.secret === "string") map.set(wh.secret, wh.organization_id);
    }
  }
  return map;
}

async function seedCtx(bootstrapOat: string): Promise<Ctx> {
  const res = await fetch("https://api.polar.sh/v1/organizations/", {
    headers: { Authorization: `Bearer ${bootstrapOat}` },
  });
  const body = (await res.json()) as OrgListResp;
  return {
    knownOrgIds: new Set(body.items.map(o => o.id)),
    bootstrapOat,
  };
}
```

## Edge cases

- **Sandbox vs production**: tokens from `sandbox-api.polar.sh` return 401 on `api.polar.sh` and vice versa. Probe both or key the ownership context by environment hint (env var name suffix, co-located `POLAR_ENV`).
- **Expired OAT**: returns 401 → `unknown`. Don't assume `other` on 401, because the admin bootstrap might also be expired. Surface the error.
- **PAT (`polar_pat_*`, dashboard-only)**: user-scoped, not org-scoped. `GET /v1/organizations/` returns all orgs the user belongs to. Same intersection logic still works — any overlap is `self`.
- **OAuth2 token with org subject (`polar_at_o_*`)**: acts like an OAT for the subject org. Same probe works.
- **OAuth2 token with user subject (`polar_at_u_*`)**: returns user's orgs. Same logic.
- **Scope-restricted OAT without `organizations:read`**: `GET /v1/organizations/` may 403. Fallback: try `GET /v1/customers/?limit=1` — that response includes `organization_id` on each customer. If even that 403s, the OAT is extremely narrow (e.g. `products:read` only); then probe `GET /v1/products/?limit=1` and read `organization_id` off the product. Every Polar resource carries `organization_id`, so any successful GET leaks ownership.
- **Self-escalation guard**: does not affect read-only probes. Only relevant when rotating (creating new OATs).
- **Webhook secret reuse across endpoints**: each endpoint has an independently-generated `polar_whs_*`. Collisions are astronomically unlikely (`secrets.token_urlsafe(32)` internally).
- **Leaked webhook secret seen by admin but belonging to a different org's endpoint**: the bootstrap OAT only lists endpoints in orgs it has `webhooks:read` on. Secrets for unrelated orgs fall through to `unknown` — which is the correct answer.
- **`secret` field gets redacted in a future API version**: watch for `polar_whs_***` mask in responses. If Polar changes the `WebhookEndpoint` schema to hide `secret` on read, webhook-secret ownership collapses to `impossible` without out-of-band pairing (e.g. matching the Vercel env var name pattern to the admin's known endpoint IDs).

## Verdict summary

| Secret shape | Method | Cost | Certainty |
|---|---|---|---|
| `polar_oat_*` | Probe `GET /v1/organizations/` → intersect org ids | 1 call | High |
| `polar_at_o_*` / `polar_at_u_*` | Same probe | 1 call | High |
| `polar_pat_*` | Same probe | 1 call | High |
| `polar_whs_*` | Hash-index against admin's webhook endpoints | N at setup, 0 at query | Low-medium |

OAT rotation is the primary flow (see `../polar.md`). Webhook secret is a separate credential class that rotate-cli tracks independently; ownership detection for webhook secrets is best-effort because they were never designed as identifiable bearers.
