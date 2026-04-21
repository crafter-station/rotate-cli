---
provider: vercel-token
verdict: api-introspection
cost: 1-call
certainty: high
---

# Vercel — ownership detection

Target secrets: `VERCEL_TOKEN` (personal or team-scoped auth token). Applies to both `adapter-vercel-token` (rotates the token itself) and `consumer-vercel-env` (pushes/pulls secrets on behalf of the token). Also read by `adapter-vercel-kv` and any other adapter that piggybacks on Vercel auth. Note: `AI_GATEWAY_API_KEY` is NOT a Vercel auth token — see `ai-gateway.md`.

## Verdict

**Single API call, definitive answer.** Vercel exposes a first-class "what is this token?" endpoint: `GET /v5/user/tokens/current`. It returns the token's id, scopes (`user` or `team` + `teamId`), origin, prefix, and suffix. Combined with the admin's own `GET /v2/user` (returns `id` of "me") and optional `GET /v2/teams` (teams I'm in), ownership is resolvable deterministically.

Use case fit for rotate-cli:
- Admin runs `rotate doctor` → each known Vercel secret hits `/v5/user/tokens/current` with that secret as the bearer.
- If response's scopes contain `{ type: "user" }` → self-user scope, check `defaultTeamId` match or user `id` match against admin.
- If response contains `{ type: "team", teamId: "team_xxx" }` → check whether admin is member of that team (one extra `/v2/teams` call, cached).
- If the call 401s → token is dead / revoked / not ours → `"unknown"` or `"other"` depending on confidence.

## Strategy

Three tiers, cheapest first:

1. **Format decode (0 calls, low certainty):** Vercel auth tokens are a 24-char opaque alphanumeric string. There is no documented prefix and no embedded team id. Format alone can only confirm "looks like a Vercel token" — it cannot answer ownership. Skip unless you need a cheap first filter before hitting the API. Use regex `/^[A-Za-z0-9]{24}$/` only for sanity.

2. **API introspection of the unknown token (1 call, high certainty):** Call `GET /v5/user/tokens/current` with the secret-being-classified as the bearer. Response reveals scope (user or team) and teamId. Match against admin's user/team graph.

3. **List-match (N calls, fallback for weird cases):** `GET /v6/user/tokens` (as of 2026-04; `/v5` is still supported) lists all tokens the admin created. Each entry includes `prefix` + `suffix` (first few + last few chars of the token). If the secret's prefix/suffix matches an entry, we know it's ours. Useful when the token is revoked or can't self-introspect. ~1 call per page of tokens the admin has.

Recommended `ownedBy` flow: tier-2 primary, fall back to tier-3 on 401, skip tier-1.

## Endpoints used

### `GET /v5/user/tokens/current` (the killer primitive)
Auth: Bearer = the token being classified.
Returns:
```json
{
  "token": {
    "id": "tok_xxxxxxxxxxxxxxxx",
    "name": "my-token",
    "type": "oauth2-token",
    "prefix": "xYza",
    "suffix": "PqR0",
    "origin": "manual",
    "scopes": [
      { "type": "team", "teamId": "team_abc123", "origin": "manual", "createdAt": 1712... }
    ],
    "createdAt": 1712...,
    "activeAt": 1713...,
    "expiresAt": null
  }
}
```
Key fields for ownership: `scopes[*].type` (`"user"` | `"team"`) and `scopes[*].teamId`.

**"current" is a magic tokenId.** Docs state: "The special value 'current' may be supplied, which returns the metadata for the token that the current HTTP request is authenticated with." This avoids any need to know the tokenId up front.

### `GET /v2/user` (admin-side identity)
Auth: Bearer = admin's own Vercel token.
Returns `user.id`, `user.username`, `user.defaultTeamId`. Cache this once per `rotate doctor` session. Used to answer "is the current token's user scope me?"

### `GET /v2/teams` (admin-side team graph)
Auth: Bearer = admin's own Vercel token.
Returns paginated `teams[]` with `{ id, slug, name, membership: { role, teamRoles } }`. Cache this once per session. Used to answer "is the current token's team one I belong to?"

A token scoped to a team I'm in but for which I'm not OWNER still shows up here. To answer "does admin have billing control" specifically, check `membership.role === "OWNER"` (or `"BILLING"` depending on app policy).

### `GET /v6/user/tokens` (enumeration fallback)
Auth: Bearer = admin's own Vercel token.
Only returns tokens the admin created. Response includes `prefix` and `suffix` but never the full token. To list-match an unknown token string, hash by first-4 + last-4 chars. Useful when:
- The unknown token was revoked (401 on `/tokens/current`).
- You want to prove "I created this" rather than just "I can use this".

## Implementation hints (pseudocode)

```ts
type Ownership = "self" | "other" | "unknown";
type OwnershipResult = {
  verdict: Ownership;
  scope: "user" | "team";
  teamId?: string;
  teamRole?: string;         // OWNER|MEMBER|... when team-scoped
  adminCanBill: boolean;     // true iff admin is OWNER of the token's team, or user-scope == admin
  confidence: "high" | "medium" | "low";
  reason: string;
};

async function ownedByVercel(
  secret: string,
  adminCtx: { adminUserId: string; adminTeams: Map<string, TeamMembership> },
): Promise<OwnershipResult> {
  // Tier 2: introspect the unknown token itself.
  const res = await fetch("https://api.vercel.com/v5/user/tokens/current", {
    headers: { Authorization: `Bearer ${secret}` },
  });

  if (res.status === 401 || res.status === 403) {
    return {
      verdict: "unknown",
      scope: "user",
      adminCanBill: false,
      confidence: "low",
      reason: "token dead or revoked",
    };
  }

  if (!res.ok) {
    return {
      verdict: "unknown",
      scope: "user",
      adminCanBill: false,
      confidence: "low",
      reason: `vercel /tokens/current ${res.status}`,
    };
  }

  const { token } = (await res.json()) as { token: VercelTokenMeta };
  const teamScope = token.scopes?.find((s) => s.type === "team");
  const userScope = token.scopes?.find((s) => s.type === "user");

  if (teamScope) {
    const membership = adminCtx.adminTeams.get(teamScope.teamId);
    if (membership) {
      return {
        verdict: "self",
        scope: "team",
        teamId: teamScope.teamId,
        teamRole: membership.role,
        adminCanBill: membership.role === "OWNER" || membership.role === "BILLING",
        confidence: "high",
        reason: "team-scoped, admin is member",
      };
    }
    return {
      verdict: "other",
      scope: "team",
      teamId: teamScope.teamId,
      adminCanBill: false,
      confidence: "high",
      reason: "team-scoped, admin not in team",
    };
  }

  if (userScope) {
    // user-scoped tokens cannot be cross-user. If introspection worked, the
    // token belongs to *some* user — check against admin.
    const who = await fetch("https://api.vercel.com/v2/user", {
      headers: { Authorization: `Bearer ${secret}` },
    });
    if (!who.ok) {
      return {
        verdict: "unknown",
        scope: "user",
        adminCanBill: false,
        confidence: "low",
        reason: "user scope but /v2/user failed",
      };
    }
    const body = (await who.json()) as { user: { id: string; username: string } };
    const self = body.user.id === adminCtx.adminUserId;
    return {
      verdict: self ? "self" : "other",
      scope: "user",
      adminCanBill: self,
      confidence: "high",
      reason: self ? "user-scoped, matches admin" : "user-scoped, different user",
    };
  }

  return {
    verdict: "unknown",
    scope: "user",
    adminCanBill: false,
    confidence: "low",
    reason: "no scopes returned",
  };
}
```

Cache `adminCtx` once per CLI invocation. Expect one `GET /v2/user` + one paginated `GET /v2/teams` on first call, then reuse.

## Edge cases

- **Limited-form user response.** If admin's `VERCEL_TOKEN` is missing privileges to read full user data, `/v2/user` returns `{ limited: true, ... }`. Still contains `id`, so identity comparison works.
- **SAML-enforced teams.** If a team has SAML enforced and admin's session isn't SAML-authenticated, `/v2/teams` entry will be `{ limited: true, limitedBy: ["mfa"|"scope"] }`. You still get `id` + `slug` + `membership.role`, which is enough for ownership. Don't panic on `limited: true`.
- **OAuth2 vs manual tokens.** `token.type` can be `"oauth2-token"` (third-party integration acted on admin's behalf) or `"oauth-app"` or simple manual. Ownership is the same (the token is admin's if team/user check passes). If `origin` is `"chatgpt"` or `"v0"` — that's still admin's token, just created by integration.
- **Team-scoped but admin is `VIEWER` only.** Ownership is "self" (admin can use the token), but `adminCanBill = false`. Rotate-cli should gate rotation on `adminCanBill` for destructive ops or at minimum warn.
- **Revoked / leaked tokens.** `token.revokedAt` and `token.leakedAt` may be non-null even on `/v5/user/tokens/current`. Actually — if revoked, the call will 401 first. `leakedAt` can appear via the admin's own `/v6/user/tokens` listing; flag these in rotate-cli as "rotate immediately".
- **`expiresAt` soon.** `/tokens/current` returns `expiresAt` (ms epoch). Useful side-signal: if < 24h away, mark as `needs-rotate` regardless of ownership.
- **Tokens created by the Vercel CLI vs dashboard.** Both show up in `/v6/user/tokens` with distinguishable `origin` (`"manual"` from dashboard; `"github"`, `"google"` etc. from OAuth bootstrap). Ownership logic doesn't need this, but rotate-cli UI should surface it.
- **Cross-account tokens are impossible.** A Vercel token can only act on one scope — either a specific team or the user's own namespace. There is no "works across multiple teams you belong to" token. So the billing-control question reduces to: is admin a member (team scope) or the same user (user scope)?
- **`AI_GATEWAY_API_KEY` masquerade.** If rotate-cli sees a var literally named `AI_GATEWAY_API_KEY` holding a string that starts with `vck_`, do NOT route it through this flow. It's a different credential with no `/v5/user/tokens/current` equivalent. Pointer: `ai-gateway.md`.
- **Rate limits.** Vercel's public rate limit isn't documented per-endpoint, but empirically `/v2/user` and `/v5/user/tokens/current` are generous (several hundred calls/min/token). Still, cache `adminCtx` aggressively across the whole `rotate doctor` run.
- **Stripe-style "test mode" equivalent?** Vercel has no test/live bifurcation for auth tokens. All tokens are production against the live control plane.
