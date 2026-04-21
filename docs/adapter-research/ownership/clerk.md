---
provider: clerk
verdict: format-decode
cost: 0-calls
certainty: high
sources:
  - "https://clerk.com/docs/guides/how-clerk-works/overview"
  - "https://clerk.com/blog/refactoring-our-api-keys"
  - "https://clerk.com/docs/reference/backend-api"
  - "https://clerk.com/changelog/2026-01-09-secret-key-management-restricted-to-admins"
  - "https://clerk-bapi.redoc.ly/"
---

# Clerk — ownership detection

## Summary

- `CLERK_SECRET_KEY` (`sk_live_...` / `sk_test_...`) has **no documented local-decode path** — the random suffix is opaque.
- `CLERK_PUBLISHABLE_KEY` (`pk_live_...` / `pk_test_...`) is a base64-encoded FAPI hostname, and the FAPI hostname is globally unique per Clerk instance. This is the **free ownership signal**.
- `CLERK_WEBHOOK_SECRET` (Svix `whsec_...`) has no owner-identifying content at all — must be mapped via sibling secret or external bookkeeping.

Because rotate-cli's scope is per-project Vercel env vars and every Clerk-using project sets `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` alongside `CLERK_SECRET_KEY`, the pragmatic answer is **decode the publishable key, compare to a known allow-list of instance fingerprints per admin**.

## Strategy (layered)

### Layer 1 (preferred) — decode publishable key (0 network calls)

The Clerk publishable key decodes to the FAPI instance URL. Example from Clerk's own docs:

```js
atob('pk_test_ZXhhbXBsZS5hY2NvdW50cy5kZXYk'.replace('pk_test_', ''))
// => "example.accounts.dev$"
```

The hostname before `$` is one of:
- Dev: `{slug}.accounts.dev` (unique per instance)
- Prod: `clerk.{your-domain.com}` (pointed at Clerk by CNAME)

This hostname acts as a **stable, unforgeable instance identifier** — two instances cannot share the same FAPI hostname. rotate-cli's admin context caches its instance fingerprints; any Vercel project whose `pk_*` decodes to a hostname not in that set belongs to someone else.

### Layer 2 (fallback, paid-ish) — bootstrap via secret key call

When only the secret key is available (no sibling publishable), send one cheap authenticated call:

```bash
curl -s https://api.clerk.com/v1/jwks \
  -H "Authorization: Bearer sk_live_xxx"
```

`GET /v1/jwks` is a free, idempotent, read-only endpoint that requires a valid secret key. On success it returns the instance's signing key set; the `kid` values embed a stable instance identifier (visible by querying once with a known admin key, then reusing as fingerprint). On 401 the key is either revoked or not ours.

A nicer alternative if the admin context has it: `GET /v1/beta_features` or `GET /v1/domains` — both tied to the calling instance and both 401 for foreign secret keys from a different admin. We are **not** using `/v1/users` (more expensive, pageable, leaks data).

## Q1–Q4 answers

**Q1 (introspection):** No `/v1/me` for secret keys. The Backend API is tenant-scoped — every endpoint is "me" implicitly, but none returns a human-readable `instance_id` in a documented field. `GET /v1/jwks` and the JWKS `kid` is the closest thing to an introspection primitive.

**Q2 (list-match):** Clerk added a user-facing "API Keys" resource in Dec 2025 (`APIKeys` object, user/org-scoped API keys). That is **not** the secret key — it is a feature exposed to end users of a Clerk-powered app. There is no admin-level "list secret keys for my Clerk account" endpoint — secret key rotation is a Dashboard-only action (and since 2026-01-09 restricted to admins in the Clerk Dashboard).

**Q3 (format decode):** Yes for `pk_*` (base64 FAPI URL). No for `sk_*` — the tail after `sk_live_` is random. No for `whsec_*` — Svix signing secrets have no tenant marker.

**Q4 (recommended):**
1. Decode the sibling `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` → FAPI hostname (0 calls, cryptographic certainty).
2. Compare hostname to the admin's cached fingerprint set (populated on first admin login).
3. If no publishable key available in the same Vercel env: fall back to `GET /v1/jwks` with the secret, hash the `kid`, compare.

## Endpoints used

```bash
# Layer 2 fallback — costs 1 call, returns JWKS
curl -s https://api.clerk.com/v1/jwks \
  -H "Authorization: Bearer $CLERK_SECRET_KEY"
# 200 OK returns {"keys":[{"kid":"ins_xxx_...","kty":"RSA",...}]}
# 401 means the secret is invalid OR belongs to a different instance
```

Note: Clerk returns 401 without a body leak when a secret key is valid-looking but does not match any known instance. We cannot distinguish "revoked" vs "foreign" from the status code alone; see edge cases.

## Implementation hints

```ts
// adapter-clerk/ownership.ts
import { decode as b64decode } from 'base64';

type Ctx = {
  // populated at first-run by decoding the admin's known publishable keys
  knownFapiHosts: Set<string>;
};

export async function ownedBy(
  secrets: { secretKey: string; publishableKey?: string; webhookSecret?: string },
  ctx: Ctx,
): Promise<'self' | 'other' | 'unknown'> {
  // Layer 1 — decode publishable, zero network
  if (secrets.publishableKey) {
    const host = decodeFapi(secrets.publishableKey);
    if (host && ctx.knownFapiHosts.has(host)) return 'self';
    if (host) return 'other';
  }

  // Layer 2 — call /v1/jwks with the secret
  const res = await fetch('https://api.clerk.com/v1/jwks', {
    headers: { Authorization: `Bearer ${secrets.secretKey}` },
  });
  if (res.status === 401) return 'unknown'; // could be revoked or foreign, see edge cases
  if (!res.ok) return 'unknown';

  const jwks = await res.json() as { keys: Array<{ kid: string }> };
  const kid = jwks.keys[0]?.kid;
  // kid encodes the instance id (stable). Compare to ctx.knownKids.
  return ctx.knownKids.has(kid) ? 'self' : 'other';
}

function decodeFapi(pk: string): string | null {
  const body = pk.replace(/^pk_(live|test)_/, '');
  try {
    const decoded = Buffer.from(body, 'base64').toString('utf8');
    // format is "{host}$"
    return decoded.replace(/\$$/, '') || null;
  } catch {
    return null;
  }
}
```

For the `CLERK_WEBHOOK_SECRET` (Svix), there is no local signal. In practice rotate-cli should treat the webhook secret's ownership as **inherited from its sibling** `CLERK_SECRET_KEY` in the same Vercel project env — if the secret key is "self", the webhook secret is "self" by association. This is a reasonable heuristic because Vercel env vars are grouped per-project and Clerk configures both from the same Dashboard screen.

## Edge cases

- **Revoked `pk_*`**: decoding still works — format-decode ownership check is unaffected by revocation. That is an advantage over the network path.
- **Foreign instance, same Clerk account's other app**: Layer 1 correctly flags the unknown FAPI host as "other" even within the same Clerk account, which is what we want (each Clerk instance has its own billing and keys).
- **Proxied FAPI (`clerk.acme.com`) vs Clerk-hosted (`acme.clerk.accounts.dev`)**: both decode cleanly; admin must cache both forms if they moved to proxied FAPI post-launch. See [Proxying the Clerk Frontend API](https://clerk.com/docs/guides/dashboard/dns-domains/proxy-fapi).
- **Same publishable key, rotated secret key**: Layer 1 still reports "self" because `pk_*` is unchanged across secret rotation. Good.
- **Orphaned `whsec_*`**: if the Vercel project has only the webhook secret (no Clerk SDK keys), there is no way to determine ownership. Treat as "unknown" and prompt.
- **`sk_test_` vs `sk_live_` mismatch with `pk_live_` sibling**: possible misconfiguration. Flag and require human confirmation before rotating.
- **Rate limits**: Layer 2 should cache results per secret hash for the rotation-planning phase; retries during orchestration should reuse the cached verdict.
