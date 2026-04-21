---
provider: resend
verdict: list-match
cost: N-calls
certainty: medium
sources:
  - "https://resend.com/docs/api-reference/api-keys/create-api-key"
  - "https://resend.com/docs/api-reference/api-keys/list-api-keys"
  - "https://resend.com/docs/dashboard/domains/introduction"
  - "https://resend.com/changelog/new-api-key-permissions"
  - "https://github.com/resend/resend-go/blob/main/api_keys_test.go"
---

# Resend — ownership detection

## Summary

Resend has **no `/me` endpoint**, and its list endpoint returns only `{id, name, created_at, last_used_at}` — no key prefix, no last-four, no token fragment. The key body `re_xxxxxxxxx` has no parseable tenant marker.

The only stable ownership fingerprint available via Resend's API is the **set of verified domains** associated with the key's team. Every Resend team has at least one verified sending domain, and domain ownership is effectively externally verifiable (DNS TXT records). rotate-cli can call `GET /domains` with the key and intersect the returned domain list with the admin's known-good domain set.

Verdict: `list-match` with a fingerprint derived from `GET /domains`. Cost is 1 call per candidate key. Certainty is medium because a key can belong to a team that legitimately shares a domain with another (rare) team, and because a "sending" key without full-access permissions will return 401 on `/domains`.

## Strategy

### Primary — domain fingerprint

1. On `rotate login resend`, Hunter's master Resend key calls `GET https://api.resend.com/domains` once. Cache the returned domain list (`{id, name, status, region, created_at}`) as the admin's `knownDomains` fingerprint.
2. For each Vercel env var holding `re_...`:
   - Call `GET /domains` with that key.
   - If 200 and the returned domain set is a subset of `knownDomains` → `self`.
   - If 200 and the domain set disjoint from `knownDomains` → `other`.
   - If 401/403 (the key is a send-only restricted key and cannot list domains) → fall through to secondary strategy.

### Secondary — send-only key probe

Resend introduced per-permission API keys in 2024 ("Full access" vs "Sending access"). Sending-only keys cannot read `/domains`. For those:

- Call `POST /emails` **only to an allowed `from` domain** to verify the key is scoped to a domain we own. Use `?dry=true` if Resend exposes it, or a no-op body that 400s with a specific validation error revealing the `from` domain scope.
- As of the last research pass (2026-04-20), Resend's send endpoint does **not** offer a free dry-run. This probe would actually send a test email or bounce on validation — not acceptable in a rotation tool.
- Therefore sending-only keys should degrade to Tier 3: infer ownership from sibling Vercel env vars in the same project (same pattern as the Anthropic adapter).

### Tertiary — sibling env-var inheritance

If `RESEND_API_KEY` is in a Vercel project where `CLERK_SECRET_KEY` / other adapters already resolved to "self", treat the Resend key as "self" by association. Surface the inference in the plan preview before rotating.

## Endpoints used

```bash
# Primary — list domains; needs full-access key
curl -s https://api.resend.com/domains \
  -H "Authorization: Bearer $RESEND_API_KEY"

# 200 response shape (relevant fields):
{
  "data": [
    {
      "id": "4dd369bc-...",
      "name": "clerk.dev",
      "status": "verified",
      "created_at": "2024-11-01T...",
      "region": "us-east-1"
    }
  ]
}

# Liveness-only fallback for sending-only keys — lists domains by name
# succeeds for any scope that can send, but exact response body differs.
# NOT reliable for ownership, only for "is this key alive".
curl -sI https://api.resend.com/emails/invalid-id \
  -H "Authorization: Bearer $RESEND_API_KEY"
# 404 with body = key is valid; 401 = key is dead or wrong.
```

Rate limit: default 2 req/s per team (see Resend docs on rate limits). `GET /domains` counts against this pool. Batch rotations should serialize.

## Implementation hints

```ts
// adapter-resend/ownership.ts

type Ctx = {
  knownDomainIds: Set<string>;     // id per Resend domain
  knownDomainNames: Set<string>;   // name fallback for display
  vercelSiblingOwnership?: 'self' | 'other' | 'unknown';
};

export async function ownedBy(
  secret: string,
  ctx: Ctx,
): Promise<'self' | 'other' | 'unknown'> {
  const res = await fetch('https://api.resend.com/domains', {
    headers: { Authorization: `Bearer ${secret}` },
  });

  if (res.status === 401) return 'unknown'; // key revoked or invalid
  if (res.status === 403) {
    // key is sending-only; cannot read domains.
    return ctx.vercelSiblingOwnership ?? 'unknown';
  }
  if (!res.ok) return 'unknown';

  const body = (await res.json()) as {
    data: Array<{ id: string; name: string }>;
  };

  const domainIds = body.data.map(d => d.id);
  if (domainIds.length === 0) return 'unknown'; // fresh team with no domains

  const allKnown = domainIds.every(id => ctx.knownDomainIds.has(id));
  if (allKnown) return 'self';

  const someKnown = domainIds.some(id => ctx.knownDomainIds.has(id));
  if (someKnown) {
    // partial overlap — surface for human review.
    // In practice this means two Resend teams share a verified domain,
    // which Resend does not support today, so this is likely a bug.
    return 'unknown';
  }

  return 'other';
}
```

Bootstrap on `rotate login resend`:

```ts
async function seedCtx(masterKey: string): Promise<Ctx> {
  const res = await fetch('https://api.resend.com/domains', {
    headers: { Authorization: `Bearer ${masterKey}` },
  });
  const body = await res.json();
  return {
    knownDomainIds: new Set(body.data.map((d: any) => d.id)),
    knownDomainNames: new Set(body.data.map((d: any) => d.name)),
  };
}
```

## Edge cases

- **Sending-only keys**: the majority of production `RESEND_API_KEY` values are scoped to "Sending access" (Resend recommends this for prod). `GET /domains` returns 403. Must fall through to sibling inference — the single weakest point of this adapter.
- **Restricted-by-domain keys**: Resend's permission model allows restricting a key to one specific domain. `GET /domains` with such a key returns only that one domain. If it overlaps with `knownDomainIds`, still a correct "self" → good.
- **Revoked key**: 401 on every endpoint. rotate-cli cannot distinguish revoked-and-ours from revoked-and-theirs → treat as `unknown` and require human confirmation before revoking (reading `/api-keys` with the master key and cross-checking by name is a dashboard workflow, not an API one).
- **Freshly created team with no verified domain**: `GET /domains` returns `{data: []}`. Cannot fingerprint. Degrade to sibling inference + prompt.
- **Team member with access to multiple teams**: Resend keys are team-scoped, so a single key only ever represents one team. Good — no multi-team ambiguity.
- **Domain transferred between teams**: Resend does not currently support transferring verified domains between teams, so the fingerprint is effectively stable. If this changes, the admin ctx needs a refresh on each rotate run.
- **List key endpoint**: `GET /api-keys` intentionally returns no token data (`id, name, created_at, last_used_at` only). Using this endpoint to match against a raw `re_...` is **impossible**. Confirm on implementation via resend-go test fixtures ([`api_keys_test.go`](https://github.com/resend/resend-go/blob/main/api_keys_test.go)).
- **Feature request**: Ask Resend to add `last_four` or `key_prefix` on `GET /api-keys` (like Stripe, OpenAI). This would upgrade the verdict to `list-match` with high certainty and remove the need for sibling inference. Worth filing.
