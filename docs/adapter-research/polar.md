---
type: adapter-research
service: polar
created: 2026-04-20
status: draft
sources:
  - "https://polar.sh/docs/api-reference/introduction"
  - "https://polar.sh/docs/integrate/authentication"
  - "https://polar.sh/docs/integrate/oat"
  - "https://polar.sh/docs/integrate/webhooks/endpoints"
  - "https://polar.sh/docs/integrate/webhooks/delivery"
  - "https://api.polar.sh/openapi.json"
  - "https://github.com/polarsource/polar/blob/main/server/polar/organization_access_token/endpoints.py"
  - "https://github.com/polarsource/polar/blob/main/server/polar/organization_access_token/service.py"
  - "https://github.com/polarsource/polar/blob/main/server/polar/webhook/endpoints.py"
  - "https://github.com/polarsource/polar/blob/main/server/polar/webhook/service.py"
  - "https://github.com/polarsource/polar/blob/main/server/polar/webhook/schemas.py"
  - "https://github.com/polarsource/polar/blob/main/server/polar/oauth2/constants.py"
  - "https://github.com/polarsource/polar-js/blob/main/docs/sdks/organizationaccesstokens/README.md"
---

# Polar adapter research

Goal: rotate `POLAR_ACCESS_TOKEN` and `POLAR_WEBHOOK_SECRET` across 35 Vercel env vars without disrupting checkouts, subscriptions, or webhook delivery.

## Auth flow

Polar API has four bearer token types. Only one is relevant for rotate-cli.

| Type | Prefix | Source | Rotatable via API | Notes |
|------|--------|--------|-------------------|-------|
| Organization Access Token (OAT) | `polar_oat_` | `POST /v1/organization-access-tokens/` **or** Dashboard | yes, fully | Scoped to one organization. Recommended for server use. |
| OAuth2 Access Token (user subject) | `polar_at_u_` | `/v1/oauth2/token` via auth code flow | no (refresh only) | For partner integrations / user-authorized apps. |
| OAuth2 Access Token (org subject) | `polar_at_o_` | `/v1/oauth2/token` | no (refresh only) | Issued to OAuth2 clients acting on an org. |
| Personal Access Token (PAT) | (undocumented prefix, likely `polar_pat_`) | Dashboard only (https://polar.sh/settings) | no | Tied to a user, not an org. Not used in server integrations. |

Production base URL: `https://api.polar.sh/v1`. Sandbox: `https://sandbox-api.polar.sh/v1`. Tokens from one environment do not work in the other.

Request header for every authenticated call:
```
Authorization: Bearer polar_oat_xxxxxxxxxxxxxxxxx
```

**Self-escalation guard (important).** When the caller is an OAT, `_validate_scopes_within_caller` in `organization_access_token/service.py` rejects any create/update where requested scopes exceed the caller's scopes. A rotation bootstrap token therefore needs `organization_access_tokens:write` plus every scope the app consumes (typically `products:*`, `checkouts:*`, `orders:*`, `subscriptions:*`, `customers:*`, `webhooks:*`, `benefits:*`). Without those, the new OAT can be minted with only a subset.

Token hashing: Polar hashes OATs with `HMAC(settings.SECRET, token)` and stores only the hash (`get_token_hash` in `polar.kit.crypto`). The plaintext `token` is returned exactly once in `201 Created` — after that, only the opaque UUID `id` is available.

Leak protection: GitHub Secret Scanning auto-revokes any `polar_oat_*` pushed to a public repo and emails the org admins. This is not something rotate-cli needs to handle, but it means a botched rotation (plaintext leaking into git) is not silent.

## Endpoints (create / verify / revoke / list)

Core API at `https://api.polar.sh/v1`. All endpoints require `Authorization: Bearer` with either `oat`, `pat`, or `oidc` (OAuth2) subject. The `organization_access_tokens` resource is tagged `public` and `mcp` in the OpenAPI spec, so it is stable. Note that its llms.txt index entry is missing — the endpoints exist regardless (verified against live `https://api.polar.sh/openapi.json`, 2026-04-20).

### Create

```
POST /v1/organization-access-tokens/
Authorization: Bearer <bootstrap OAT>
Content-Type: application/json
Required scopes: organization_access_tokens:write

Body (OrganizationAccessTokenCreate):
{
  "comment": "rotate-cli 2026-04-20",            // required, free text label
  "scopes": ["products:read", "checkouts:write", ...],  // required, subset of caller scopes
  "expires_in": "P90D",                           // optional ISO-8601 duration, null = never
  "organization_id": "1dbfc517-...-..."           // required if caller is User/PAT; omit when caller is OAT
}

201 Response (OrganizationAccessTokenCreateResponse):
{
  "organization_access_token": {
    "id": "uuid",
    "created_at": "...", "modified_at": "...",
    "organization_id": "...",
    "comment": "rotate-cli 2026-04-20",
    "scopes": ["products:read", ...],
    "expires_at": "2026-07-19T...Z",
    "last_used_at": null
  },
  "token": "polar_oat_<52+ chars>"   // only time this is returned
}
```

TypeScript SDK: `polar.organizationAccessTokens.create({ comment, scopes, expiresIn, organizationId })`.

### List

```
GET /v1/organization-access-tokens/?organization_id={uuid}&page=1&limit=100&sorting=-created_at
Required scopes: organization_access_tokens:read (or :write)

Returns ListResource<OrganizationAccessToken>. Sort fields: created_at, comment, last_used_at, organization_id.
```

Use case for rotate-cli: after minting the new token, enumerate tokens whose `comment` starts with the previous rotation's label to find the old `id` for deletion.

### Get / Update

```
PATCH /v1/organization-access-tokens/{id}
Body: { "comment": "...", "scopes": [...] }   // both optional
Required scopes: organization_access_tokens:write
```

There is no separate `GET /{id}` on the public surface. `get` is only exposed through `list` filtering.

### Revoke / Delete

```
DELETE /v1/organization-access-tokens/{id}
204 No Content
Required scopes: organization_access_tokens:write
```

Soft-deletes the token (repository.soft_delete). Once deleted, any subsequent request with that token returns 401. There is no grace period — the token is dead as soon as the DELETE returns.

### OAuth2 revoke (do not use for OATs)

```
POST /v1/oauth2/revoke
Body: { token, client_id, client_secret, token_type_hint? }
```

This endpoint revokes OAuth2 access tokens / refresh tokens (`polar_at_u_*`, `polar_at_o_*`, `polar_rt_*`). It is **not** applicable to OATs. Requires an OAuth2 client's `client_id` + `client_secret`, not a bearer token.

## metadata shape

Minimum payload for creating a rotation-pair OAT:

```json
{
  "comment": "rotate-cli rotation @ 2026-04-20T05:00:00Z",
  "scopes": [
    "products:read", "products:write",
    "checkouts:read", "checkouts:write",
    "checkout_links:read", "checkout_links:write",
    "orders:read", "orders:write",
    "subscriptions:read", "subscriptions:write",
    "customers:read", "customers:write",
    "benefits:read", "benefits:write",
    "webhooks:read", "webhooks:write",
    "metrics:read",
    "organization_access_tokens:write"
  ],
  "expires_in": "P90D"
}
```

Notes on metadata:
- **No free-form metadata object.** Polar OATs have only `comment` (string) as user-visible metadata. Encode rotation ID, env, git SHA inside `comment` as a delimited string (e.g. `rotate-cli|prod|2026-04-20|git:abc1234`). Keep under ~255 chars; no schema-enforced max but dashboard UI truncates long strings.
- `expires_in` accepts ISO-8601 duration (`P90D`, `P30D`, `PT1H`). When set, `expires_at` is computed as `utc_now() + expires_in` at creation time. Missing `expires_in` = never expires (null).
- `scopes` cannot exceed caller's scopes (see Auth flow). Plan bootstrap scope list up front; rotate-cli should fail fast if the seed OAT lacks coverage.
- Full scope enum (62 values) lives at `#/components/schemas/AvailableScope` in the spec; superset list mirrored in the codebase at `server/polar/auth/scope.py`. Do not hardcode scopes that are not in `AvailableScope`.

## Webhook secret rotation (separate concern)

Webhook secrets (`polar_whs_*`) are a **distinct credential** from OATs. They sign outbound webhook payloads using the Standard Webhooks spec. Rotation is performed per webhook endpoint, not per organization.

### Endpoint

```
PATCH /v1/webhooks/endpoints/{id}/secret
Authorization: Bearer <OAT with webhooks:write>
(no request body)

200 Response (WebhookEndpoint):
{
  "id": "uuid",
  "url": "https://...",
  "secret": "polar_whs_<44 chars>",   // new secret, returned plaintext, once
  "events": [...],
  "format": "raw|discord|slack",
  "organization_id": "...",
  "enabled": true,
  ...
}
```

Source: `webhook_service.reset_endpoint_secret` simply generates a new token with prefix `polar_whs_` and overwrites `WebhookEndpoint.secret`. There is no dual-secret window — the old secret is invalidated immediately.

TypeScript SDK: `polar.webhooks.resetWebhookEndpointSecret({ id })`.

### Listing endpoints to rotate

```
GET /v1/webhooks/endpoints?organization_id={uuid}&page=1&limit=100
Required scopes: webhooks:read
```

For rotate-cli, iterate every endpoint and PATCH `/secret` on each, collecting the new secrets into the Vercel update batch.

### Cannot rotate secret via PATCH on the endpoint itself

The public `WebhookEndpointUpdate` schema has a `secret` field but it is `SkipJsonSchema` + `deprecated` ("The secret is now generated on the backend"). Sending it through `PATCH /v1/webhooks/endpoints/{id}` is silently ignored on the public JSON schema. Use the `/secret` subresource.

### Standard Webhooks caveat

Signatures are HMAC-SHA256 over `{id}.{timestamp}.{body}` with the secret **base64-decoded**. Consumers using `@polar-sh/sdk/webhooks`' `validateEvent` handle this automatically. Hand-rolled verifiers must base64-decode the `polar_whs_*` string before HMAC — a detail the docs call out explicitly as a common gotcha.

### Webhook delivery reliability envelope

Relevant for rotation race conditions:
- Polar retries failed deliveries up to 10 times with exponential backoff.
- Requests time out at 10s (soft recommendation: respond within 2s).
- 10 consecutive failures auto-disable the endpoint; re-enable requires manual dashboard action.

This means: if the new secret lands in Polar but not yet in Vercel, the receiver will return 403 from signature-mismatch and burn through retry budget. Don't let a rotation gap last more than ~10 failed deliveries worth of real traffic.

## Gotchas

1. **No dual-validity window.** Both OAT rotation (DELETE old) and webhook secret rotation (PATCH /secret) cut the old credential instantly. There is no Stripe-style "old key works for 24h" mode. Order of operations for rotate-cli must be:
   1. Create new OAT (returns plaintext once).
   2. Reset webhook secret (returns plaintext once).
   3. Write both to Vercel env vars for all 35 projects.
   4. Trigger Vercel redeploy (or wait for next) so new env is live.
   5. Only then DELETE the old OAT.
   Webhook secret has no equivalent "delete" — the reset call replaces it atomically. Any webhook fired between the reset call and the Vercel deploy will fail signature verification.

2. **`organization_access_tokens:write` is required on the caller.** A minimal `POLAR_ACCESS_TOKEN` in production probably does not have this scope. rotate-cli needs a separate bootstrap OAT (or dashboard-minted seed) with the full scope set. Store that one out-of-band (1Password, not Vercel).

3. **Scope subset rule.** Even with `organization_access_tokens:write`, an OAT cannot mint another OAT with scopes it does not itself hold. The bootstrap token is effectively the scope ceiling.

4. **OAT creation endpoint is missing from `llms.txt`** and from the user-facing mintlify docs sidebar, which only describes dashboard creation. The endpoint is real and stable (tagged `public` in the live OpenAPI), but this explains why most third-party walkthroughs say "only from the dashboard."

5. **No `POST /revoke` for OATs.** Revocation is always `DELETE /v1/organization-access-tokens/{id}` by UUID. You must have the `id`, not the plaintext token. If the plaintext was lost, use `GET /list` and match by `comment`.

6. **`last_used_at` is the only freshness signal.** There is no "active / stale" flag. rotate-cli can use `last_used_at` older than N days as a secondary safety check before deletion.

7. **Sandbox and production are fully isolated.** Rotate per environment. Do not assume an OAT works across both.

8. **Rate limits.** 500 req/min (prod) or 100 req/min (sandbox) per organization. With 35 projects this is plenty, but the rotation writer must be throttled by the Vercel side, not Polar.

9. **Webhook endpoint may be org-wide (one secret for all 35 projects) or per-project.** If per-project, rotation is N secrets in N env vars. Worth auditing via `GET /v1/webhooks/endpoints?organization_id={org}` before wiring rotate-cli — the number of endpoints determines whether `POLAR_WEBHOOK_SECRET` is a singleton or a map.

10. **`secret` field on `WebhookEndpointCreate` is accepted (min_length 32) but deprecated.** Do not let users supply their own secret through rotate-cli; always let Polar generate it so it carries the `polar_whs_` prefix used by signature helpers.

11. **IP allowlist drift.** New webhook source IPs added 2025-10-27 (`74.220.50.0/24`, `74.220.58.0/24`). Not a rotation concern, but worth noting if a Vercel firewall rule is in play.

12. **Public OpenAPI spec is the source of truth**, not docs. The OpenAPI at `https://api.polar.sh/openapi.json` includes endpoints (like the OAT CRUD and the webhook `/secret` subroute) that the mintlify docs and `llms.txt` omit.

## Verdict

**Rotation of `POLAR_ACCESS_TOKEN` (OAT): fully supported via API, build a first-class adapter.**

`POST /v1/organization-access-tokens/` → capture plaintext → propagate → `DELETE /v1/organization-access-tokens/{id}`. No dual-window, so the propagation step must be transactional from rotate-cli's perspective. This is the cleanest secret class in the research so far — tight CRUD, public OpenAPI, official SDK methods (`polar.organizationAccessTokens.{create,list,update,delete}`).

**Rotation of `POLAR_WEBHOOK_SECRET`: supported via API, single atomic call.**

`PATCH /v1/webhooks/endpoints/{id}/secret` returns the new secret; old secret dies immediately. Safe if Vercel deploy follows within seconds; dangerous if there's a minutes-long gap under live traffic (Polar retries absorb a few misses, auto-disable at 10 consecutive fails). Adapter should support rotating all endpoints in an org in one call site.

**Blockers for MVP: none.** Both credentials are first-class API-rotatable. The only operational constraint is ordering: mint → write → delete/reset, not the other way around. Subscriptions and orders are unaffected by either rotation — they reference `organization_id`, not the token or secret used to query them.

**Suggested adapter shape (rotate-cli):**
- `polar.createCredential()` → `POST /v1/organization-access-tokens/` with config-driven scope list + `comment` encoding rotation metadata.
- `polar.revokeCredential(id)` → `DELETE /v1/organization-access-tokens/{id}`.
- `polar.listCredentials({ commentPrefix })` → `GET /v1/organization-access-tokens/` for cleanup.
- `polar.rotateWebhookSecret(endpointId)` → `PATCH /v1/webhooks/endpoints/{id}/secret`.
- `polar.listWebhookEndpoints()` → `GET /v1/webhooks/endpoints` for discovering the N endpoints to rotate.
- Treat OAT + webhook secret as two separate credential classes in the registry; they rotate on independent schedules.
