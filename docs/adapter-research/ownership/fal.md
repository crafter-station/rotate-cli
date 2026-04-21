---
provider: fal-ai
verdict: list-match
cost: 1-call (warm) | N-calls (cold setup per team)
certainty: medium
sources:
  - "https://fal.ai/docs/platform-apis/v1/keys/list"
  - "https://fal.ai/docs/platform-apis/v1/keys/create"
  - "https://fal.ai/docs/api-reference/platform-apis/for-keys"
  - "https://fal.ai/docs/documentation/setting-up/authentication"
  - "https://fal.ai/docs/api-reference/platform-apis/for-accounts"
---

# fal.ai — ownership detection

Target env vars: `FAL_API_KEY`, `FAL_KEY` (the SDK expects `FAL_KEY`; `FAL_API_KEY` is a common alias).

## Summary

fal.ai has **no introspection endpoint**. There is no `/v1/me`, no `/v1/user`, no `/v1/team` in the Platform API — confirmed against the `for-accounts` section (billing + FOCUS report + model access controls, no identity). The Platform APIs Hunter has access to are `/v1/keys` (CRUD) and billing-adjacent reports. None accept a candidate key and return "here's your team".

Keys **are scoped to the account (personal or team) that created them** per the authentication docs. An admin key from team A cannot list, delete, or create keys for team B. This is the wedge: if the admin's bootstrap ADMIN key can `GET /v1/keys` and the candidate `key_id` appears in that list, the candidate belongs to the same team as the admin.

So the strategy is **list-match by `key_id`**, extracted from the candidate's format (`key_id:key_secret`).

## Strategy

### Format-decode (partial) → list-match

1. Parse the candidate. Canonical format is `key_id:key_secret`. Both halves are opaque; `key_id` is a short alphanumeric (e.g. `abc123def456`, observed 8-24 chars).
2. Extract `key_id = candidate.split(":")[0]`.
3. Look up `key_id` in the admin's cached `GET /v1/keys?limit=100` result (paginated via `cursor`).
4. Hit → `self`. Miss → `other` *if admin's team list is exhaustive*; else `unknown`.

The only network call at query-time is into the local cache. Cold setup: one paginated list per team the admin belongs to. Since fal "teams" are distinct accounts (the admin must switch team context in the dashboard before creating a key), the admin might need **N bootstrap ADMIN keys** (one per team) to build a complete reverse index. In practice Hunter has ~1-2 teams.

### Why no network probe of the candidate

The docs explicitly say only ADMIN-scoped keys can call `/v1/keys`. A candidate that's an API-scoped key (the common case — that's what's in `FAL_KEY`) will 403 on any management endpoint. Hitting a model endpoint (e.g. `POST https://fal.run/fal-ai/flux/dev`) would succeed but cost credits and returns only model output — no identity info. There is no free liveness probe that returns team context.

### Fallback: hash-compare on creator metadata

`GET /v1/keys?expand=creator_info` returns `creator_nickname` and `creator_email` per key. If `key_id` matches, we also verify `creator_email === ctx.selfEmail` as a consistency check. If `key_id` misses but the candidate's `creator_email` (not knowable without list) — skip this, list-match on `key_id` is already authoritative within the admin's team scope.

## Endpoints used

Base: `https://api.fal.ai/v1`. Auth: `Authorization: Key {ADMIN_KEY}` (note: `Key ` prefix, not `Bearer`).

```bash
# Build reverse index at rotate-cli setup.
# Repeat per team — admin must have an ADMIN key issued *from each team context*.
curl "https://api.fal.ai/v1/keys?limit=100&expand=creator_info" \
  -H "Authorization: Key $FAL_ADMIN_KEY_TEAM_A"

# Response:
# {
#   "keys": [
#     {
#       "key_id": "abc123def456",
#       "alias": "rotate-cli 2026-04-20",
#       "scope": "API",
#       "created_at": "2026-04-20T...Z",
#       "creator_email": "railly@clerk.dev"
#     },
#     ...
#   ],
#   "next_cursor": "...",
#   "has_more": true
# }
```

```bash
# Follow cursor until has_more=false
curl "https://api.fal.ai/v1/keys?limit=100&cursor=$NEXT" \
  -H "Authorization: Key $FAL_ADMIN_KEY_TEAM_A"
```

No endpoint to introspect a candidate directly. `DELETE /v1/keys/{key_id}` would 404 for a foreign key (204 for own, 204 for non-existent — indistinguishable). Don't abuse that as an ownership oracle: it leaks intent to fal's audit log and risks accidental deletion.

## Implementation hints (pseudocode)

```ts
// adapter-fal/ownership.ts

type TeamContext = {
  teamLabel: string;            // user-supplied, e.g. "clerk" or "personal"
  adminKey: string;             // fal ADMIN key scoped to this team
  knownKeyIds: Set<string>;     // lazily populated
};

type Ctx = {
  teams: TeamContext[];
  selfEmail: string;
};

export async function ownedBy(
  secret: string,
  ctx: Ctx,
): Promise<"self" | "other" | "unknown"> {
  const [keyId, keySecret] = secret.split(":");
  if (!keyId || !keySecret) return "unknown";

  for (const team of ctx.teams) {
    if (team.knownKeyIds.size === 0) await warmTeamIndex(team);
    if (team.knownKeyIds.has(keyId)) return "self";
  }

  // Not found in any team the admin can see. Could be another team or revoked.
  // Distinguish by probing a cheap fal model endpoint with the candidate:
  const live = await fetch("https://fal.run/health", {
    headers: { Authorization: `Key ${secret}` },
  });
  if (live.status === 401 || live.status === 403) return "unknown"; // revoked or malformed
  return "other"; // key works, just not in admin's teams
}

async function warmTeamIndex(team: TeamContext): Promise<void> {
  let cursor: string | undefined;
  do {
    const qs = new URLSearchParams({ limit: "100", expand: "creator_info" });
    if (cursor) qs.set("cursor", cursor);
    const res = await fetch(`https://api.fal.ai/v1/keys?${qs}`, {
      headers: { Authorization: `Key ${team.adminKey}` },
    });
    if (!res.ok) throw new Error(`fal list failed for ${team.teamLabel}: ${res.status}`);
    const body = await res.json();
    for (const k of body.keys ?? []) team.knownKeyIds.add(k.key_id);
    cursor = body.has_more ? body.next_cursor : undefined;
  } while (cursor);
}
```

## Edge cases

- **Single-string form (legacy)**: older fal SDKs accept the full colon-joined `FAL_KEY` as one string. Split on first `:`. If no colon, it's either a legacy admin-only key or a malformed env — treat as `unknown`.
- **Modern secret prefix (`fal_sk_...` / `sk_live_...`)**: docs disagree. The `key_secret` half may or may not have a stable prefix. `key_id` (before the colon) is what matters for list-match — do not regex on `key_secret`.
- **Hunter has 1 team only**: covers ~100% of current fal usage. The multi-team branch is future-proofing. Hunter's current fal admin key is personal-scoped.
- **ADMIN key bootstrap is dashboard-only**: fal does not let you mint an ADMIN key from API. The admin context must be seeded via `fal.ai/dashboard/keys`. Rotate-cli treats this as a one-time manual step per team.
- **Team switching in dashboard**: when Hunter creates an ADMIN key while "team: clerk" is selected, that key lists clerk's team keys only. To cover personal, a second ADMIN key is needed with "personal" selected at creation time.
- **Deleted keys**: `GET /v1/keys` does not include deleted keys. A candidate whose `key_id` used to exist but was revoked → misses the index → falls through to the liveness probe, which returns 401 → `unknown`. Correct behavior.
- **Pagination drift**: during a long rotation window, new keys may be created concurrently. Warm the index at the start of the rotate-cli run; tolerate a 0.1% miss rate by treating ambiguous `other` as "manual review".
- **Liveness probe cost**: `fal.run/health` is a made-up placeholder — fal does not document a billing-free ping. In practice, the cheapest probe is `GET https://queue.fal.run/` or any model's queue status endpoint, which 401s on bad keys without charging. Verify before shipping.
- **`key_id` collision across teams**: key_ids are short (~12 chars). fal does not publish a uniqueness guarantee. Treat them as team-scoped identifiers — if two admin teams show the same `key_id`, prefer the team whose `creator_email === ctx.selfEmail`.
- **API-scope keys (the 95% case)**: cannot introspect themselves. `list-match` on their `key_id` via an admin key is the only path.

## Verdict summary

| Secret shape | Method | Cost | Certainty |
|---|---|---|---|
| `key_id:key_secret` (API scope) | Extract `key_id`, lookup in admin's `/v1/keys` index | 0 calls at query (warm) | Medium |
| Colon-joined ADMIN key | Same | 0 calls at query (warm) | Medium |
| Legacy single-string | Treat as `unknown` unless split succeeds | — | Low |

**Why medium, not high**: admin must bootstrap one ADMIN key per team, and the index is a point-in-time snapshot. If Hunter has a key in a team the admin has not been provisioned for, it will read as `other` instead of the more accurate `unknown`. The liveness probe tiebreaker is non-trivial to implement without burning credits, so the current recommendation is: accept `other` as the default for unknown teams and surface the `key_id` + `alias` (from any cached list) to the human reviewer when rotate-cli hits this case.
