---
provider: turso
verdict: format-decode (connection URL) + list-match (auth tokens)
cost: 0-calls (URL) | N-calls warm then 0 (auth token)
certainty: high (URL) | medium (auth token alone)
---

# Turso — ownership detection

Target env vars: `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, plus per-env variants (dev/staging/prod × url/token).

## Strategy

Turso is the easiest of the four to detect ownership for, because the **connection URL itself encodes both database name and org slug**.

### A. `TURSO_DATABASE_URL` — format-decode, 0 network calls
Format: `libsql://{database-name}-{organization-slug}.turso.io`

Example: `libsql://my-agent-db-hunter.turso.io` → db = `my-agent-db`, org = `hunter`.

The org slug is the definitive ownership signal. If admin's Platform API token is scoped to org `hunter` and the URL contains `-hunter.turso.io`, it's "self". Pure regex, cryptographic certainty (host is DNS-validated by libsql driver).

⚠️ Ambiguity: database names can contain hyphens, so splitting on the last `-` before `.turso.io` is the correct parse (db = everything before last hyphen, org = everything after).

### B. `TURSO_AUTH_TOKEN` — JWT, but payload is minimal
Turso DB auth tokens are JWTs signed with Ed25519. The payload is intentionally sparse (minimal claim set, per Turso's auth saga blog):

- `exp` — expiration
- `iat` — issued at
- `p` — permissions object (e.g. `{ ro: { ns: [...] } }` for read-only scoping)
- `id` — used for user API tokens, not DB tokens

**Crucially, the DB auth token does NOT embed the database name or org slug in its claims.** The token's identity comes from **which URL it's presented to** — the libsql server validates the signature using the database's JWKS. A token for db `foo-hunter` presented to `bar-hunter.turso.io` will fail signature verification.

This means: you **cannot determine** ownership of a loose `TURSO_AUTH_TOKEN` without its paired URL. In practice in rotate-cli:
- If the token is co-located with a `TURSO_DATABASE_URL` in the same env → use the URL, trivial.
- If the token is alone → fall back to list-match: iterate `GET /v1/organizations/{org}/databases` for each known org, mint a probe against each, see which one accepts it. Expensive and lossy.

### C. Recommended resolution order

1. Look for co-located `TURSO_DATABASE_URL` or `DATABASE_URL=libsql://...` → parse host → match against admin's known org slugs. **0 calls, high certainty**.
2. If the env var *is* the URL → same.
3. If token alone → decode JWT to confirm it's a Turso-shaped token (exp + p claim present), then fall back to list-match probe (expensive, medium certainty).
4. Else → "unknown".

## Endpoints used

Base: `https://api.turso.tech`

- `GET /v1/organizations` — admin's orgs (Platform API token needed).
- `GET /v1/organizations/{org}/databases` — list databases in an org. Response includes `Name`, `Hostname`, `DbId`, `regions`, `group`.
- `POST /v1/organizations/{org}/databases/{db}/auth/validate` — *does not exist*; there's no official "is this token valid for this db?" endpoint. Closest proxy is to use the token to hit the database's libsql endpoint (`wss://{db-org}.turso.io`) — but that's networking against the DB, not a control-plane call.

Admin auth: `Authorization: Bearer {TURSO_PLATFORM_TOKEN}` — minted via `turso auth api-tokens mint rotate-cli --org {slug}`.

## Implementation hints (pseudocode)

```ts
type AdminCtx = {
  selfOrgSlugs: Set<string>;   // e.g. { "hunter", "crafter-station" }
  dbIndex: Map<string, { org: string; db: string; hostname: string }>; // built lazily
};

function ownedBy(secret: string, coLocatedVars: Record<string, string>, ctx: AdminCtx): "self" | "other" | "unknown" {
  // Tier 1: secret IS a libsql URL
  const url = looksLikeLibsqlUrl(secret) ? secret : coLocatedVars.TURSO_DATABASE_URL ?? coLocatedVars.DATABASE_URL;
  if (url && /^libsql:\/\//i.test(url)) {
    const host = new URL(url.replace("libsql://", "https://")).host; // my-db-hunter.turso.io
    const m = host.match(/^(.+)-([a-z0-9-]+)\.turso\.io$/i);
    if (!m) return "unknown";
    // tricky: db name can contain hyphens. Split on LAST hyphen.
    const [full, _dbIgnored, _orgIgnored] = m;
    const hostname = full; // "my-db-hunter"
    const lastDash = hostname.lastIndexOf("-");
    const db = hostname.slice(0, lastDash);
    const org = hostname.slice(lastDash + 1);
    if (ctx.selfOrgSlugs.has(org)) return "self";
    return "other";
  }

  // Tier 2: JWT token alone — verify it's Turso-shaped, otherwise unknown
  if (secret.startsWith("eyJ")) {
    const payload = decodeJwtPayloadUnverified(secret);
    if (!payload || typeof payload.exp !== "number") return "unknown";
    // Turso DB tokens have 'p' (permissions) claim or are completely empty past exp/iat.
    // No db/org identity in claims — cannot determine ownership from token alone.
    return "unknown"; // prefer "unknown" over guessing
  }

  return "unknown";
}

async function warmDbIndex(adminToken: string, orgs: string[]): Promise<Map<string, { org: string; db: string; hostname: string }>> {
  const idx = new Map();
  for (const org of orgs) {
    const dbs = await fetch(`https://api.turso.tech/v1/organizations/${org}/databases`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    for (const db of dbs.databases) {
      idx.set(db.Hostname, { org, db: db.Name, hostname: db.Hostname });
    }
  }
  return idx;
}
```

## Edge cases

- **Hyphenated db names**: `libsql://my-cool-db-hunter.turso.io` — split on LAST hyphen before `.turso.io`. The org slug side is the authoritative one (org slugs are also lowercase, hyphen-allowed, but db names are fully user-controlled so there's no disambiguating rule besides listing).
- **Verification via list**: if regex gives ambiguous split, the cheapest disambiguation is admin's `dbIndex` reverse-map by full hostname. `my-cool-db-hunter.turso.io` as hostname → lookup wins.
- **Self-hosted libsql**: hostname won't match `.turso.io`. Detection falls through to "unknown" — correct, it's not Turso-managed.
- **`authToken` in URL query string**: old pattern `libsql://db-org.turso.io?authToken=...` — extract both URL (for org) and token (for validity) separately. The `authToken=` query is flagged as bad practice but rotate-cli may see it in user envs.
- **Replica endpoints**: primary and replica share the same hostname; no distinction needed for ownership.
- **Embedded replicas** (local file + sync URL): the sync URL is still `libsql://db-org.turso.io` — detect from sync URL var, not the local path.
- **Platform API token** (`TURSO_PLATFORM_TOKEN` itself): different beast — used by admin to *perform* rotations. Ownership detection doesn't apply; it's the admin's own credential.
- **Expired token**: JWT decodes cleanly; `exp < now` is obvious. Return "unknown" since no URL context.

## Verdict summary

| Secret shape | Method | Cost | Certainty |
|---|---|---|---|
| `libsql://db-org.turso.io` (URL) | Regex host split on last `-` | 0 calls | High |
| Co-located URL + token | Use URL | 0 calls | High |
| `TURSO_AUTH_TOKEN` alone | Format-check only | 0 calls | Low (unknown) |
| `PLATFORM_TOKEN` | N/A — admin's own | 0 calls | High (self by definition) |

**Recommendation for rotate-cli**: always resolve ownership via the co-located `TURSO_DATABASE_URL`. Never try to determine ownership from an orphan `TURSO_AUTH_TOKEN` — flag it "unknown" and ask Hunter to provide the URL pair.

## Sources

- [Authentication - Turso](https://docs.turso.tech/sdk/authentication) — JWT auth, URL format `libsql://[DB]-[ORG].turso.io`.
- [Authorization API: Platform Saga Part II](https://turso.tech/blog/authorization-api-platform-saga-part-2-448f7622) — user API token JWT claims (`exp`, `iat`, `id`), distinction vs DB tokens.
- [Generate Database Auth Token](https://docs.turso.tech/api-reference/databases/create-token) — `POST /v1/organizations/{org}/databases/{db}/auth/tokens`, permissions payload shape.
- [Turso CLI](https://docs.turso.tech/cli/auth/api-tokens) — `turso auth api-tokens mint` command.
