---
provider: elevenlabs
verdict: api-introspection
cost: 1-call
certainty: medium
sources:
  - "https://elevenlabs.io/docs/api-reference/user/get"
  - "https://elevenlabs.io/docs/api-reference/authentication"
  - "https://elevenlabs.io/docs/api-reference/service-accounts/api-keys/list"
  - "https://elevenlabs.io/docs/api-reference/service-accounts/api-keys/create"
  - "https://elevenlabs.io/docs/overview/administration/workspaces/service-accounts"
  - "https://elevenlabs.io/docs/overview/administration/workspaces/overview"
---

# ElevenLabs — ownership detection

Target env var: `ELEVENLABS_API_KEY` (opaque, passed via `xi-api-key` header).

## Summary

ElevenLabs has a `GET /v1/user` endpoint that works with any live `xi-api-key` and returns `{ user_id, xi_api_key_preview, first_name, seat_type, subscription: { tier, ... } }`. That is the only self-introspection primitive — and critically, **it does not return a workspace_id**. The `seat_type` field (`workspace_admin` | `workspace_member` | `workspace_lite_member` | null) indicates role within a workspace but does not name the workspace.

So the strategy is: one call to `/v1/user` with the candidate key, match `user_id` (and optionally `subscription.tier`) against the admin's known set. The admin side is seeded by running the same call with the admin's own key during `rotate login elevenlabs`.

Certainty is **medium** rather than high because workspace identity is inferred (user_id + seat_type is a proxy), not asserted. Two different service-account keys in the same workspace return different `user_id` values — each service account *is* a user. The `seat_type` distinguishes SA users from human admins, but two workspaces can both have SAs named "rotate-cli" with distinct user_ids.

## Strategy

### Primary path: `/v1/user` + user_id intersection

1. Call `GET /v1/user` with `xi-api-key: <candidate>`.
2. If 401/403 → `unknown` (revoked, malformed, or wrong account).
3. Read `user_id`. Match against `ctx.knownUserIds` — a set seeded from:
   - The admin's own human account `user_id` (via `rotate login`).
   - Each known service-account `user_id` (discovered via workspace member listing during bootstrap).
4. Hit → `self`. Miss → `other`.

### Tiebreaker: `subscription.tier` + `first_name`

`subscription.tier` (Free, Starter, Creator, Pro, Scale, Business, Enterprise) is workspace-level on multi-seat plans — all users in the same workspace report the same tier. `first_name` on service accounts is the SA name chosen at creation. Together they corroborate identity when `user_id` alone is ambiguous.

### Why not format-decode

`xi-api-key` values have no documented prefix. Examples uniformly use `ELEVENLABS_API_KEY` as a placeholder; the actual secret is ~50-60 opaque chars. No `sk_`, no `eyJ`, no JSON payload. Format-decode is ruled out.

### Why not list-match

Listing keys requires knowing the `sa_id` (`GET /v1/service-accounts/{sa_id}/api-keys`). There is no global `/v1/keys` or `/v1/workspace/api-keys` endpoint. Without `sa_id`, you can't iterate. And even per-SA, the list returns `key_id` + `hint` (last-4 preview) — not the full plaintext — so direct match on the candidate string is impossible. You can hash the candidate and compare to `hashed_xi_api_key` in the list if that field is ever exposed; as of 2026-04-20 it is returned per the known schema, but hashing semantics are undocumented. List-match is theoretically possible via `hashed_xi_api_key` comparison but fragile.

Therefore: `/v1/user` introspection is the cheap, reliable primary path.

## Endpoints used

Base: `https://api.elevenlabs.io`. Regional mirrors: `api.us.elevenlabs.io`, `api.eu.elevenlabs.io`, `api.in.elevenlabs.io`. Regional selection is at workspace creation time and fixed — using the wrong regional base returns 401 even with a valid key, so the adapter must try each base or store the region in admin context.

```bash
# Primary introspection — works for human keys AND service-account keys
curl https://api.elevenlabs.io/v1/user \
  -H "xi-api-key: $ELEVENLABS_API_KEY"

# 200 response shape (UserResponseModel):
# {
#   "user_id": "abc123",
#   "xi_api_key_preview": "****ab12",
#   "first_name": "Railly",
#   "seat_type": "workspace_admin",
#   "subscription": {
#     "tier": "Creator",
#     "character_count": 12345,
#     "character_limit": 1000000,
#     "status": "active",
#     ...
#   },
#   "is_new_user": false,
#   ...
# }
```

```bash
# Bootstrap-time: enumerate service accounts in admin's workspace
curl https://api.elevenlabs.io/v1/workspace/members \
  -H "xi-api-key: $ELEVENLABS_ADMIN_KEY"

# Note: this endpoint exists but the schema is partially documented.
# Each member has { user_id, email, seat_type, joining_date, ... }.
# Filter seat_type=="workspace_admin" vs SA type to separate humans from SAs.
```

No workspace-id primitive: the API does not expose a stable `workspace_id` on the caller side. Workspaces are implicit — the set of user_ids in `GET /v1/workspace/members` defines the workspace.

## Implementation hints (pseudocode)

```ts
// adapter-elevenlabs/ownership.ts

type Ctx = {
  knownUserIds: Set<string>;      // admin + all SA user_ids in admin's workspaces
  knownTiers: Set<string>;        // e.g. { "Creator", "Pro" } — workspace tiers admin belongs to
  regionalBase: string;           // https://api.elevenlabs.io or regional mirror
};

type MeResponse = {
  user_id: string;
  first_name?: string;
  seat_type?: "workspace_admin" | "workspace_member" | "workspace_lite_member" | null;
  subscription?: { tier: string; status: string };
};

export async function ownedBy(
  secret: string,
  ctx: Ctx,
): Promise<"self" | "other" | "unknown"> {
  const res = await fetch(`${ctx.regionalBase}/v1/user`, {
    headers: { "xi-api-key": secret },
  });
  if (res.status === 401 || res.status === 403) return "unknown";
  if (!res.ok) return "unknown";

  const me = (await res.json()) as MeResponse;

  if (ctx.knownUserIds.has(me.user_id)) return "self";

  // Tiebreaker: same tier + seat_type is SA in multi-seat workspace
  // — weak signal, don't upgrade to "self" alone, but flag for review.
  const tierMatch = me.subscription?.tier && ctx.knownTiers.has(me.subscription.tier);
  const isSA = me.seat_type && me.seat_type !== "workspace_admin";
  if (tierMatch && isSA) {
    // Ambiguous: could be a newly-added SA not in ctx yet, OR another workspace at same tier.
    // Return "unknown" to force manual confirmation rather than silently "other".
    return "unknown";
  }

  return "other";
}

async function seedCtx(adminKey: string, regionalBase: string): Promise<Ctx> {
  const me = await fetchMe(adminKey, regionalBase);
  const ctx: Ctx = {
    knownUserIds: new Set([me.user_id]),
    knownTiers: new Set(me.subscription?.tier ? [me.subscription.tier] : []),
    regionalBase,
  };
  // Enumerate service accounts in admin's workspace
  const members = await fetchWorkspaceMembers(adminKey, regionalBase);
  for (const m of members) ctx.knownUserIds.add(m.user_id);
  return ctx;
}
```

## Edge cases

- **Regional base mismatch**: key from `api.us.elevenlabs.io` workspace returns 401 on `api.elevenlabs.io`. The adapter must either know the region from admin context or retry across all four bases. In practice, `api.elevenlabs.io` proxies to the correct region for most accounts but not all.
- **Personal (single-seat) account**: no service accounts, no workspace. `/v1/user` still returns `user_id` + `subscription`, and `seat_type` may be null. Match purely on `user_id`.
- **Free tier workspace**: service accounts are gated to multi-seat plans. A key on a Free tier will have `seat_type: null`. Treat like personal account.
- **Revoked key**: 401 with body `{ "detail": { "status": "invalid_api_key" } }` — map to `unknown`.
- **Rate-limited admin bootstrap**: `/v1/user` is cheap but not free — within the management API group. ElevenLabs has not published explicit RPS but burst-limit ~5/sec for safety.
- **Key enabled=false**: a disabled SA key returns 401 on `/v1/user`. rotate-cli cannot distinguish disabled from revoked via this probe; the admin's `GET /v1/service-accounts/{sa_id}/api-keys` is needed to tell them apart — but that requires knowing `sa_id` first.
- **Workspace renamed / tier upgraded**: tier changes invalidate the tier tiebreaker. Re-seed ctx when tiers change.
- **`hashed_xi_api_key` field**: returned by the SA keys list endpoint. Theoretically, `sha256(secret)` could match `hashed_xi_api_key` for list-match. ElevenLabs has not documented the hash algorithm. If confirmed, this would upgrade the verdict to high certainty + 0-call at query time. Worth a probe during implementation.
- **User with multiple workspaces**: `/v1/user` returns the "primary" workspace's user record. If a human is in two workspaces with different SA keys, ownership of a specific SA key requires matching against the correct workspace's member list. Rare; current architecture suggests each workspace has its own admin seed in `ctx.teams[]` (parallel to fal's multi-team design).
- **Leading/trailing whitespace in env var**: ElevenLabs 401s on trimmed-but-still-matching keys sometimes (observed in 2025 bug reports). Trim defensively before the call.
- **Key permissions: scoped to TTS only**: may 403 on `/v1/user`. Fallback: `GET /v1/voices` — scoped keys with `voices_read` return their user context implicitly via workspace voice library. No direct user_id in that response though; this fallback gives liveness but not identity. If `/v1/user` 403s, flip to `unknown`.

## Verdict summary

| Secret shape | Method | Cost | Certainty |
|---|---|---|---|
| Personal `xi-api-key` | `GET /v1/user` → match `user_id` | 1 call | High |
| Service account `xi-api-key` | Same, plus SA user_id must be pre-indexed | 1 call | Medium |
| Scoped key (no user read) | Fallback to `/v1/voices` liveness → `unknown` | 1 call | Low |

The 1-call ceiling is tight; the medium certainty is entirely about workspace disambiguation when user_ids cross context boundaries. For Hunter's current use (single workspace, maybe 1-2 SAs), this is effectively high-certainty.
