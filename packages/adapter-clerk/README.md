# @rotate/adapter-clerk

Clerk adapter for rotate-cli. It creates, verifies, lists, and revokes Clerk secret keys through Clerk PLAPI.

## Supported Operations

| Operation | Supported | API |
|---|---:|---|
| `create` | Yes | `POST /v1/instances/{instance_id}/api_keys` |
| `verify` | Yes | `GET /v1/me` using the new key |
| `revoke` | Yes | `DELETE /v1/instances/{instance_id}/api_keys/{key_id}` |
| `list` | Yes | `GET /v1/instances/{instance_id}/api_keys` |
| `ownedBy` | Yes | Decode co-located publishable key, with JWKS fallback |

`revoke` is idempotent. A missing key returns success so repeated revocation attempts are safe.

## Auth Setup

The adapter uses Clerk CLI auth when available:

```bash
clerk login
```

It also supports an environment fallback:

```bash
export CLERK_PLAPI_TOKEN="plapi_live_..."
```

## Ownership detection

Clerk secret keys (`sk_live_...` and `sk_test_...`) are opaque, so the preferred ownership signal is the co-located `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`. Clerk publishable keys decode to a Frontend API hostname such as `example.accounts.dev` or `clerk.example.com`. The adapter compares that decoded hostname to known Clerk FAPI host fingerprints passed in ownership preload data.

When the decoded host is known, ownership returns `self` with high confidence. When the decoded host is valid but not known, ownership returns `other` with high confidence. If no publishable key or known host fingerprints are available, the adapter can fall back to `GET /v1/jwks` with the candidate secret key and compare returned `kid` values to known JWKS fingerprints; failures, authorization errors, and rate limits degrade to `unknown`.

Clerk webhook secrets (`whsec_...`) do not contain owner-identifying data. When a webhook secret is checked with a sibling `CLERK_SECRET_KEY` from the same project environment, ownership is inherited from that sibling with medium confidence. Orphaned webhook secrets return `unknown`.

## Config Example

```yaml
version: 1

secrets:
  - id: clerk-prod
    adapter: clerk
    metadata:
      instance_id: ins_abc123
    consumers:
      - type: vercel-env
        params:
          project: production-app
          var_name: CLERK_SECRET_KEY
```
