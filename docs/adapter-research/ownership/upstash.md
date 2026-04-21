---
provider: upstash
verdict: list-match (REST token) + format-decode (REST URL)
cost: 0-calls (URL lookup after warm index) | N-calls to build index
certainty: high (URL) | high (token hash match)
---

# Upstash — ownership detection

Target env vars: `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, plus Vercel KV aliases (`KV_REST_API_URL`, `KV_REST_API_TOKEN`, `KV_URL`, `REDIS_URL`, `KV_REST_API_READ_ONLY_TOKEN`). Vercel KV is Upstash under the hood since 2024; identical detection logic.

## Strategy

Upstash REST tokens are **opaque** (not JWTs). The token string `AXW_ASQgOTZh...=` is a base64-encoded blob that Upstash's gateway uses to route + authorize, but it is not publicly documented as parseable. No `iss`/`ref`/`aud` claims to read.

However, the `UPSTASH_REDIS_REST_URL` companion var is almost always co-located and **does** identify the database:

Format: `https://{adjective}-{noun}-{number}.upstash.io`
Example: `https://relaxed-puma-43216.upstash.io`

The hostname slug is assigned at db creation and is globally unique. Upstash's management API `GET /v2/redis/databases` lists all dbs admin can see, including the `endpoint` hostname and `rest_token`. Build a reverse index once, match cheaply after.

### Resolution order

1. Co-located `UPSTASH_REDIS_REST_URL` (or Vercel KV `KV_REST_API_URL`) → regex hostname → match against admin's db index. **0 calls after warm**.
2. If token alone: hash the token against the `rest_token` value of every db in admin's index. Upstash lists plaintext `rest_token` in the management API response, so this works reliably. **0 calls after warm, high certainty** — but can only say "self" if match; "unknown" otherwise (cannot distinguish "other org" from "not Upstash at all").
3. Probe via REST: call `GET {url}/ping` with the token. 200 confirms token is valid for that URL. Combined with (1), this is a sanity check, not primary identity.
4. Else → "unknown".

## Endpoints used

### Management API (admin)
Base: `https://api.upstash.com`
Auth: HTTP Basic — `EMAIL:API_KEY`.

- `GET /v2/redis/databases` — list all Redis databases. Response is an array. Each entry includes:
  - `database_id` (uuid)
  - `database_name`
  - `endpoint` (e.g. `relaxed-puma-43216.upstash.io`)
  - `rest_token` ← the plaintext REST token, matches `UPSTASH_REDIS_REST_TOKEN`
  - `read_only_rest_token`
  - `user_email` / `team_id` (ownership)
  - `password` (redis-protocol password, different from REST token)
- `GET /v2/teams` — admin's teams. Personal account = implicit team.
- `GET /v2/redis/database/{id}` — single db detail.

### Per-database REST endpoint
`https://{endpoint}.upstash.io/ping` with `Authorization: Bearer {token}` → returns `{"result":"PONG"}`. Validates token matches endpoint. Does not return owner metadata — just 200/401. Useful for sanity, not primary detection.

## Implementation hints (pseudocode)

```ts
type UpstashDb = {
  id: string;
  endpoint: string;            // "relaxed-puma-43216.upstash.io"
  restToken: string;
  readOnlyRestToken: string;
  teamId: string | null;
  userEmail: string;
};

type AdminCtx = {
  selfTeamIds: Set<string>;
  selfEmails: Set<string>;
  dbByEndpoint: Map<string, UpstashDb>;   // built from /v2/redis/databases
  dbByRestToken: Map<string, UpstashDb>;  // sha256(token) -> db
};

function ownedBy(secret: string, coLocatedVars: Record<string, string>, ctx: AdminCtx): "self" | "other" | "unknown" {
  // Tier 1: REST URL present
  const url =
    coLocatedVars.UPSTASH_REDIS_REST_URL ??
    coLocatedVars.KV_REST_API_URL ??
    (looksLikeUpstashUrl(secret) ? secret : undefined);

  if (url) {
    const m = url.match(/^https?:\/\/([a-z]+-[a-z]+-\d+)\.upstash\.io/i);
    if (m) {
      const endpoint = `${m[1]}.upstash.io`;
      const db = ctx.dbByEndpoint.get(endpoint);
      if (!db) return "other";   // admin can't see it
      return isSelfOwned(db, ctx) ? "self" : "other";
    }
  }

  // Tier 2: token alone — hash-index match
  if (/^[A-Za-z0-9_=+/-]{40,}$/.test(secret)) {
    const hit = ctx.dbByRestToken.get(sha256(secret));
    if (hit) return isSelfOwned(hit, ctx) ? "self" : "other";
    return "unknown";   // truly unknown: could be other-org or not Upstash
  }

  // Tier 3: redis:// protocol URL (Vercel KV legacy)
  if (secret.startsWith("redis://") || secret.startsWith("rediss://")) {
    const m = secret.match(/@([a-z]+-[a-z]+-\d+)\.upstash\.io/i);
    if (m) {
      const endpoint = `${m[1]}.upstash.io`;
      const db = ctx.dbByEndpoint.get(endpoint);
      return db && isSelfOwned(db, ctx) ? "self" : db ? "other" : "other";
    }
  }

  return "unknown";
}

function isSelfOwned(db: UpstashDb, ctx: AdminCtx): boolean {
  if (db.teamId && ctx.selfTeamIds.has(db.teamId)) return true;
  if (ctx.selfEmails.has(db.userEmail)) return true;
  return false;
}

async function warmIndex(email: string, apiKey: string): Promise<{ byEndpoint: Map<string, UpstashDb>; byToken: Map<string, UpstashDb> }> {
  const res = await fetch("https://api.upstash.com/v2/redis/databases", {
    headers: { Authorization: `Basic ${btoa(`${email}:${apiKey}`)}` },
  });
  const byEndpoint = new Map<string, UpstashDb>();
  const byToken = new Map<string, UpstashDb>();
  for (const db of res) {
    byEndpoint.set(db.endpoint, db);
    byToken.set(sha256(db.rest_token), db);
    byToken.set(sha256(db.read_only_rest_token), db);
  }
  return { byEndpoint, byToken };
}
```

## Edge cases

- **Vercel KV aliases**: Vercel's `@vercel/kv` package exposes `KV_URL`, `KV_REST_API_URL`, `KV_REST_API_TOKEN`, `KV_REST_API_READ_ONLY_TOKEN`. All are Upstash underneath (Vercel KV powered by Upstash since 2024). Treat all as Upstash aliases. Same endpoint regex works.
- **Read-only token**: distinct from read-write. Both are listed per-db in management response. Index both under the same `UpstashDb`.
- **Regional vs global dbs**: endpoint slug is same format either way. Global dbs may have multiple region endpoints in SDK config, but the primary `endpoint` field in management response is authoritative.
- **Custom domains / CNAMEs**: rare but possible — some users front Upstash behind their own domain. Regex fails → fall back to token hash match.
- **Vercel Marketplace dbs**: shown in admin dashboard if admin has Vercel integration linked. If not, token will not appear in admin's `rest_token` index → classified "unknown", which is correct.
- **Rotated REST token**: old token invalidates immediately on rotation; new token replaces in management API response. Warm-cache must be refreshed after rotation to avoid stale lookups — rotate-cli should invalidate its Upstash index after `POST /v2/redis/database/{id}/reset-rest-token`.
- **Free tier hard limit**: 500 commands/sec per db. `GET /ping` probes are cheap (counted as 1 command) but avoid probing on every rotation — always prefer URL match.
- **Redis protocol URL** (`rediss://default:{password}@endpoint.upstash.io:port`): the password here is the Redis-native password, not the REST token. They're related but separate strings in the management response. Ownership still resolvable via endpoint hostname.
- **QStash, Vector, Search tokens**: same account, different services. This doc is Redis-only. Vector (`UPSTASH_VECTOR_REST_URL`) and QStash (`QSTASH_TOKEN`) use similar patterns but different endpoints (`*.upstash.io` with different slug shape).

## Verdict summary

| Secret shape | Method | Cost | Certainty |
|---|---|---|---|
| `UPSTASH_REDIS_REST_URL` | Regex endpoint + db index lookup | 0 calls (warm) | High |
| `KV_REST_API_URL` (Vercel KV) | Same as above | 0 calls (warm) | High |
| `UPSTASH_REDIS_REST_TOKEN` alone | Hash-index match | 0 calls (warm) | High-if-hit, else Medium |
| `redis://` / `rediss://` URL | Regex endpoint | 0 calls (warm) | High |

## Sources

- [REST API - Upstash Documentation](https://upstash.com/docs/redis/features/restapi) — token and REST endpoint format.
- [Upstash Developer API v2](https://upstash.com/docs/devops/developer-api) — management API overview.
- [Developer API v2 Released! (blog)](https://upstash.com/blog/management-api-v2) — `GET /v2/redis/databases` listing.
- [upstash.RedisDatabase (Pulumi docs)](https://www.pulumi.com/registry/packages/upstash/api-docs/redisdatabase/) — response schema including `rest_token`, `endpoint`, `team_id`, `user_email` fields.
