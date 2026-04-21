---
provider: vercel-ai-gateway
verdict: format-decode
cost: 0-calls
certainty: medium
---

# Vercel AI Gateway — ownership detection

Target secret: `AI_GATEWAY_API_KEY`. Prefix `vck_`. Lives in the Vercel dashboard under `/[team]/~/ai-gateway/api-keys`, team-scoped, created manually. **Not a Vercel auth token.**

## Verdict

**Mostly format-decode + indirect membership check.** The AI Gateway API key surface is dashboard-only — there is **no public REST endpoint** to list, introspect, or rotate `vck_*` keys (confirmed 2026-04: `/docs/rest-api` has no `ai-gateway` section beyond inference endpoints `/v1/chat/completions` and `/v1/models`). That means:

- Zero-cost ownership: the key can be sanity-checked by prefix (`vck_` → genuine AI Gateway key).
- **Team ownership can only be determined indirectly**: by attempting an inference call and observing whether the admin's `VERCEL_TOKEN` sees an API key with matching prefix/suffix on the dashboard (which is also not a REST primitive — the only way is a headless browser scrape). Rotate-cli should not try.
- If the admin's `VERCEL_TOKEN` and the `AI_GATEWAY_API_KEY` both work and the admin only has one team, you can *assume* they belong to the same team. Multi-team admins cannot resolve this without scraping.

See `vercel-token.md` for the closely-related `VERCEL_TOKEN` flow, which IS programmatically resolvable.

## Strategy

Tiered, all cheap:

1. **Format decode (0 calls):** regex `/^vck_[A-Za-z0-9_-]{32,}$/` confirms it's genuinely an AI Gateway key rather than a mis-typed `VERCEL_TOKEN` (24-char opaque) or an OIDC JWT (starts with `eyJ`).
2. **Liveness probe (1 call):** `GET https://ai-gateway.vercel.sh/v1/models` with `Authorization: Bearer <key>`. 200 → key is alive. 401 → key is dead/revoked. This does not reveal ownership, only validity.
3. **Billing-control inference (0 calls, low certainty):** if the admin's `VERCEL_TOKEN` (from `adapter-vercel-token`) is member of exactly one team, and the `AI_GATEWAY_API_KEY` is alive, treat as same-team with `confidence: medium`. Otherwise `unknown`.

**Do NOT implement a list-match strategy.** There is no endpoint. Any attempt to do so (e.g., scraping the dashboard) is brittle and out of scope for rotate-cli v1.

## Endpoints used

### `GET https://ai-gateway.vercel.sh/v1/models` (liveness only)
Auth: `Authorization: Bearer <AI_GATEWAY_API_KEY>`.
Returns: `{ data: [{ id: "xai/grok-4.1-fast", ... }, ...] }`.
Ownership signal: **none**. Just proves the key is valid.

### `POST https://ai-gateway.vercel.sh/v1/chat/completions` (don't use for ownership)
Costs money per call. Skip entirely for ownership detection.

### There is no `/ai-gateway/api-keys` REST endpoint
Searched `vercel.com/docs/rest-api` and the OpenAPI spec (`openapi.vercel.sh`) 2026-04-21 — no AI Gateway management surface exposed. Dashboard-only.

### `GET /v2/teams` on admin's VERCEL_TOKEN (indirect)
See `vercel-token.md`. If admin belongs to exactly one team, a live `AI_GATEWAY_API_KEY` is *probably* in that team. This is inference, not proof.

## Implementation hints (pseudocode)

```ts
async function ownedByAiGateway(
  secret: string,
  adminCtx: { adminUserId: string; adminTeams: TeamMembership[] },
): Promise<OwnershipResult> {
  // Tier 1: format sanity.
  if (!/^vck_[A-Za-z0-9_-]{32,}$/.test(secret)) {
    return {
      verdict: "unknown",
      scope: "team",
      adminCanBill: false,
      confidence: "low",
      reason: "not an AI Gateway key format (missing vck_ prefix)",
    };
  }

  // Tier 2: liveness probe.
  const alive = await fetch("https://ai-gateway.vercel.sh/v1/models", {
    headers: { Authorization: `Bearer ${secret}` },
  });

  if (alive.status === 401 || alive.status === 403) {
    return {
      verdict: "unknown",
      scope: "team",
      adminCanBill: false,
      confidence: "low",
      reason: "key revoked or invalid",
    };
  }

  if (!alive.ok) {
    return {
      verdict: "unknown",
      scope: "team",
      adminCanBill: false,
      confidence: "low",
      reason: `ai-gateway /v1/models ${alive.status}`,
    };
  }

  // Tier 3: indirect inference.
  if (adminCtx.adminTeams.length === 1) {
    const team = adminCtx.adminTeams[0];
    return {
      verdict: "self",
      scope: "team",
      teamId: team.id,
      teamRole: team.role,
      adminCanBill: team.role === "OWNER" || team.role === "BILLING",
      confidence: "medium",
      reason: "key alive + admin in exactly one team; assumed same-team",
    };
  }

  return {
    verdict: "unknown",
    scope: "team",
    adminCanBill: false,
    confidence: "low",
    reason: "key alive but admin in multiple teams; cannot attribute without dashboard access",
  };
}
```

## Edge cases

- **Key created by a teammate.** An AI Gateway key created by another member of a team the admin belongs to is fully usable by admin (same team), but "billing control" is ambiguous. Rotate-cli should rotate via the dashboard only, not silently delete.
- **OIDC tokens used as `AI_GATEWAY_API_KEY`.** In Vercel-deployed apps, `VERCEL_OIDC_TOKEN` (a JWT) can authenticate the gateway instead of a static key. Detect via `secret.startsWith("eyJ")` + JWT parse. Treat as ephemeral — rotation is automatic (12h lifetime), not user-driven. OIDC tokens encode `owner_id: "team_xxx"` in the JWT payload, so ownership IS decodable from format alone for OIDC.
- **`AI_GATEWAY_API_KEY` vs `VERCEL_TOKEN` mis-label.** If the env var is literally `AI_GATEWAY_API_KEY` but the value is a 24-char opaque string (no `vck_` prefix), it's likely a mis-pasted `VERCEL_TOKEN`. Route to `vercel-token.md` flow. Emit a warning.
- **BYOK (bring-your-own-key) provider keys.** AI Gateway also accepts OpenAI/Anthropic/xAI keys provisioned via the dashboard's BYOK flow. Those are provider keys with their own rotation flow (see `openai.md`, `anthropic.md`) and are NOT `vck_*`. Do not conflate.
- **Rotation path.** No API to rotate. Rotate-cli should treat AI Gateway as `manual-assist` adapter: open dashboard URL `https://vercel.com/[team]/~/ai-gateway/api-keys`, prompt admin to create new key, paste value, disable old key. Document the team in metadata (`team_slug`) so the URL is computable without re-asking.
- **adapter-ai-gateway source bug (2026-04).** Current `adapter-ai-gateway/src/index.ts` mints tokens against `POST /v3/user/tokens` — that endpoint creates **Vercel auth tokens, not AI Gateway API keys**. The resulting `bearerToken` will NOT work as `AI_GATEWAY_API_KEY`. Either (a) the adapter is wrong and needs dashboard-only workflow, or (b) the semantics of the adapter are "rotate the Vercel token that authenticates the AI Gateway via OIDC/BYOK flow" (different contract). Flag during ownership audit.
- **Rate limits.** Gateway inference endpoints are per-key rate-limited; `/v1/models` is generous (lookup-class). Safe for doctor checks.
- **Team billing visibility.** AI Gateway usage is billed to the team that owns the key. If rotate-cli is managing keys for a team where admin is `VIEWER` only, admin technically can use the key but should not rotate it.

## Sources

- [Vercel AI Gateway Authentication docs](https://vercel.com/docs/ai-gateway/authentication-and-byok/authentication)
- [Vercel AI Gateway overview](https://vercel.com/docs/ai-gateway)
- [Vercel OIDC reference](https://vercel.com/docs/oidc/reference)
- Missing-endpoint confirmed via `https://openapi.vercel.sh/` OpenAPI spec audit 2026-04-21
