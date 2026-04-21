---
provider: openai
verdict: api-introspection
cost: 1-call
certainty: high
sources:
  - "https://help.openai.com/en/articles/9132009-how-can-i-view-the-users-or-organizations-associated-with-an-api-key"
  - "https://platform.openai.com/docs/api-reference/admin-api-keys"
  - "https://platform.openai.com/docs/api-reference/administration"
  - "https://help.openai.com/en/articles/9186755-managing-your-work-in-the-api-platform-with-projects"
---

# OpenAI — ownership detection

## Summary

OpenAI ships a cheap, purpose-built introspection endpoint: `GET https://api.openai.com/v1/me`. It accepts **the key being introspected** as the bearer token and returns the owning user plus the organizations that key grants access to. This is the ideal path — cost is 1 network call, certainty is high (OpenAI is the source of truth), no bootstrap admin key required.

Caveats:
- `sk-proj-...` project keys are scoped to a single project. Community reports show varying behavior on non-inference endpoints; `/v1/me` works but response semantics around `orgs` are less documented. Combine with a project lookup as a tiebreaker.
- `sk-admin-...` admin keys also resolve on `/v1/me` (they are issued to a user in an org) and additionally allow `GET /v1/organization/projects`, which gives a fuller picture.

## Strategy

`ownedBy(secret, ctx)`:

1. Call `GET /v1/me` with `Authorization: Bearer {secret}`.
2. If 401 → `unknown` (revoked or malformed).
3. If 200, read `orgs.data[].id`. Intersect with `ctx.knownOrgIds`.
   - Any overlap → `self`.
   - Empty intersection → `other`.
4. For sk-admin keys only, optionally follow up with `GET /v1/organization/projects` to verify project membership and distinguish "admin for this org" from "member with read-only".

The admin's `knownOrgIds` set is seeded on first rotate-cli setup: the user runs `rotate login openai` with whatever master admin key they hold, rotate-cli calls `/v1/me` once, stores the returned `orgs.data[].id` list in the admin context. Subsequent ownership checks are pure lookups against that set.

## Endpoints used

```bash
# Primary — works for user keys (sk-...) and admin keys (sk-admin-...).
# Behaviour for project keys (sk-proj-) is documented by OpenAI support but
# responses may omit the `orgs` array if the key is narrowly scoped.
curl -s https://api.openai.com/v1/me \
  -H "Authorization: Bearer $OPENAI_API_KEY"

# 200 response shape:
{
  "object": "user",
  "id": "user_abc123",
  "email": "hunter@clerk.dev",
  "name": "Railly Hugo",
  "orgs": {
    "object": "list",
    "data": [
      { "object": "organization", "id": "org_xxx", "title": "Clerk" },
      { "object": "organization", "id": "org_yyy", "title": "Personal" }
    ]
  }
}

# Optional — admin key only. Confirms project membership for sk-proj- keys.
curl -s https://api.openai.com/v1/organization/projects \
  -H "Authorization: Bearer $OPENAI_ADMIN_KEY"
```

Rate limit: `/v1/me` is in the management API tier — generous limits, no token cost. Safe to call on every rotation candidate.

## Implementation hints

```ts
// adapter-openai/ownership.ts

type Ctx = {
  knownOrgIds: Set<string>;   // admin-level orgs Hunter owns
  knownUserIds: Set<string>;  // Hunter's OpenAI user_id(s)
};

type MeResponse = {
  object: 'user';
  id: string;
  email: string;
  orgs: { data: Array<{ id: string; title: string }> };
};

export async function ownedBy(
  secret: string,
  ctx: Ctx,
): Promise<'self' | 'other' | 'unknown'> {
  const res = await fetch('https://api.openai.com/v1/me', {
    headers: { Authorization: `Bearer ${secret}` },
  });

  if (res.status === 401 || res.status === 403) return 'unknown';
  if (!res.ok) return 'unknown';

  const me = (await res.json()) as MeResponse;

  // Strong signal — user_id match means the key was minted by Hunter himself.
  if (ctx.knownUserIds.has(me.id)) return 'self';

  // Fallback signal — org overlap. Covers the case where Hunter was invited
  // to an org and minted a key under his collaborator identity.
  const orgIds = me.orgs?.data?.map(o => o.id) ?? [];
  const selfOrg = orgIds.some(id => ctx.knownOrgIds.has(id));
  if (selfOrg) return 'self';

  // Hunter has no claim on any listed org.
  if (orgIds.length > 0) return 'other';

  // Project-scoped key that did not enumerate orgs. Ambiguous.
  return 'unknown';
}
```

Pattern for the `rotate login openai` bootstrap:

```ts
async function seedCtx(masterKey: string): Promise<Ctx> {
  const me = await fetchMe(masterKey);
  return {
    knownUserIds: new Set([me.id]),
    knownOrgIds: new Set(me.orgs.data.map(o => o.id)),
  };
}
```

## Edge cases

- **`sk-proj-...` keys**: per community reports ([project key rejection thread](https://community.openai.com/t/project-api-keys-being-rejected/1088526)), some non-inference endpoints return 404 or 401 for project keys. `/v1/me` is documented to work, but `orgs.data` may be empty when the key is restricted to one project. Fallback: parse the project id from the key itself if OpenAI continues to expose a decodable segment (not documented — verify empirically before relying).
- **Revoked keys**: 401 is returned, rotate-cli should route to `unknown` and prompt before assuming ownership.
- **Multi-org admin key**: response returns all orgs the user belongs to. As long as ctx stores the full set, intersection is exact.
- **Collaborator with admin key for *someone else's* org**: `/v1/me` returns *that* org's id. Hunter's ctx.knownOrgIds does not include it → correctly reported as `other`. This is the exact scenario the question asks about.
- **Recently rotated key, stale cache**: `/v1/me` does not cache server-side meaningfully; fresh calls return current truth. Client-side caching in rotate-cli should key on hash(secret) and TTL out within the rotation planning window (minutes, not hours).
- **Rate limits**: if rotating many secrets in a batch, fan out calls to `/v1/me` with a low concurrency (e.g. 5) to stay conservative; OpenAI has not published explicit `/v1/me` RPS but it is part of the `api.management` endpoint group.
- **Scopes missing on restricted keys**: if a key has `None` permission on the management endpoints, `/v1/me` may return 403. Treat as `unknown` — restricted keys by definition cannot self-introspect and must be matched by an out-of-band hint (e.g. sibling env vars sharing the project_id).
