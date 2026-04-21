---
provider: neon
verdict: api-introspection (api-key) + format-decode (connection-string via endpoint prefix)
cost: 1-call (api-key) | 0-calls (connection-string if admin has cached project list)
certainty: high
---

# Neon — ownership detection

Target env vars: `NEON_API_KEY`, `DATABASE_URL` (the neon-connection variant), `POSTGRES_URL`, `POSTGRES_PRISMA_URL`, `DATABASE_URL_UNPOOLED`, `NEON_POSTGRES_URL`, etc.

## Strategy

Two distinct secret shapes, handled differently:

### A. `NEON_API_KEY` — opaque 64-char token
Neon keys are opaque (random bytes, not JWTs). Prefix varies: `neon_api_key_...` (personal), `neon_org_key_...` (org), `neon_project_key_...` (project-scoped). Cannot decode locally.

Use `GET /users/me` to introspect — returns the user/org the key is bound to. **This is the cheapest, highest-signal call.** A key's scope is immutable at creation time; the owner is whoever created it.

### B. `DATABASE_URL` — Postgres connection string
Format: `postgres://{user}:{pwd}@ep-{adjective}-{noun}-{random}[-pooler].{region}.aws.neon.tech/{db}?sslmode=require`

The hostname's `ep-xxx-yyy-zzz` is a **globally-unique endpoint id**. Each endpoint belongs to exactly one project, which belongs to exactly one org. This is pure format-decode — 0 network calls **if** rotate-cli has cached the admin's `GET /projects` endpoint list.

Caveat: Neon's `GET /projects/{project_id}/endpoints/{endpoint_id}` is forward-only — no reverse `GET /endpoints/{ep-xxx}` API exists. So the reverse index must be built locally by iterating admin's projects.

### Order of precedence

1. If secret is Postgres URL → regex hostname → check endpoint id against admin's cached endpoint→project map. **cost 0 after warm cache**.
2. If secret is `neon_*_key_*` → `GET /users/me` + `GET /projects` → check key's scope. **cost 1-2 calls, cached**.
3. Else → "unknown".

## Endpoints used

Base: `https://console.neon.tech/api/v2` (also `https://api.neon.tech/v2` alias).

- `GET /users/me` — returns current user (`id`, `email`, `name`, etc.). Proves "this key belongs to user X". If X is in admin's known-self set → "self".
- `GET /projects` — returns `{ projects: [{ id, name, org_id, owner_id, ... }], ... }`. Paginated; iterate with `cursor`.
- `GET /projects/{project_id}/endpoints` — returns endpoints with `{ id: "ep-xxx-yyy-zzz", host, branch_id, ... }`. Used once to build reverse index.
- `GET /organizations` — list orgs the key can see. Personal keys see all member orgs; org keys see just one.

Auth: `Authorization: Bearer {NEON_API_KEY}`. Basic identity introspection succeeds for any live key; scope-limited keys will still return `/users/me` (personal keys) or fail with 401 (project-scoped — those can only hit `/projects/{id}/...`).

## Implementation hints (pseudocode)

```ts
type AdminCtx = {
  selfUserId: string;
  selfOrgIds: Set<string>;
  endpointToProject: Map<string, { projectId: string; orgId: string }>; // built lazily
};

function ownedBy(secret: string, ctx: AdminCtx): "self" | "other" | "unknown" {
  // Tier 1: connection string — regex endpoint id
  if (secret.startsWith("postgres://") || secret.startsWith("postgresql://")) {
    const m = secret.match(/@((?:ep-[a-z0-9-]+?))(?:-pooler)?\.[a-z0-9-]+\.(?:aws|gcp|azure)\.neon\.tech/i);
    if (!m) return "unknown";
    const endpointId = m[1];                       // ep-cool-darkness-123456
    const hit = ctx.endpointToProject.get(endpointId);
    if (!hit) return "unknown";                     // admin can't see this project -> likely "other"
    return ctx.selfOrgIds.has(hit.orgId) ? "self" : "other";
  }

  // Tier 2: api key — introspect via /users/me
  if (/^neon_(api|org|project)_key_[a-z0-9]{40,}$/i.test(secret)) {
    try {
      const me = fetch("https://console.neon.tech/api/v2/users/me", {
        headers: { Authorization: `Bearer ${secret}` },
      });
      if (me.id === ctx.selfUserId) return "self";
      // it could be an org key — try /organizations
      const orgs = fetch("https://console.neon.tech/api/v2/organizations", { headers: { Authorization: `Bearer ${secret}` } });
      if (orgs.some((o: any) => ctx.selfOrgIds.has(o.id))) return "self";
      return "other";
    } catch (e) {
      // project-scoped key can't hit /users/me (403). Try listing projects it can see.
      const projects = fetch("https://console.neon.tech/api/v2/projects", { headers: { Authorization: `Bearer ${secret}` } });
      if (projects.some((p: any) => ctx.selfOrgIds.has(p.org_id))) return "self";
      return "other";
    }
  }

  return "unknown";
}

async function warmEndpointIndex(adminKey: string): Promise<Map<string, { projectId: string; orgId: string }>> {
  const map = new Map();
  const projects = await fetchAllPages("/projects", adminKey); // cursor pagination
  for (const p of projects) {
    const endpoints = await fetch(`/projects/${p.id}/endpoints`, adminKey);
    for (const ep of endpoints) map.set(ep.id, { projectId: p.id, orgId: p.org_id });
  }
  return map;
}
```

## Edge cases

- **Pooler suffix**: hostname may be `ep-xxx-pooler.region.aws.neon.tech`. Strip `-pooler` before lookup.
- **Region encoded in hostname**: `.us-east-2.aws.neon.tech` vs `.eu-central-1.gcp.neon.tech`. Endpoint id is still globally unique; region is routing hint, not identity.
- **Branched databases**: each branch has its own endpoint id. Two endpoint ids → same project, both map to same ownership.
- **Rotated/deleted endpoint**: reverse index goes stale. Re-warm on 404 from `/projects/{id}/endpoints/{ep}`.
- **Project-scoped keys**: can't hit `/users/me` (403). Fall back to `GET /projects` which returns only projects the key can access — if it's 1 project in admin's org, it's "self".
- **Password in connection string**: that's the per-role database password, not rotatable via the admin key. It does not encode project info; only the hostname does.
- **Deprecated `project=` connection option**: legacy way to pass endpoint via SNI — value is the full endpoint id. Same regex works on query param.
- **Self-hosted Neon (rare)**: hostname pattern differs, detection fails → "unknown". That's fine.

## Verdict summary

| Secret shape | Method | Cost | Certainty |
|---|---|---|---|
| `DATABASE_URL` (postgres) | Regex endpoint id + cached reverse index | 0 calls (warm) | High |
| `NEON_API_KEY` (personal) | `GET /users/me` + match self | 1 call | High |
| `neon_org_key_*` | `GET /organizations` | 1 call | High |
| `neon_project_key_*` | `GET /projects` (scoped view) | 1 call | Medium |

## Sources

- [Manage API Keys - Neon Docs](https://neon.com/docs/manage/api-keys) — prefixes `neon_api_key_`, `neon_org_key_`, `neon_project_key_`; scopes.
- [Neon API Reference](https://api-docs.neon.tech/reference/getting-started-with-neon-api) — `/users/me`, `/projects`, `/organizations`.
- [Connect from any application - Neon Docs](https://neon.com/docs/connect/connect-from-any-app) — hostname `ep-{adjective}-{noun}-{random}.region.provider.neon.tech` format.
- [Retrieve compute endpoint details](https://api-docs.neon.tech/reference/getprojectendpoint) — endpoint id requires project id (no reverse lookup endpoint).
