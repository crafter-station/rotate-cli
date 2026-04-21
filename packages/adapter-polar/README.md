# @rotate/adapter-polar

Polar adapter for rotate-cli. It rotates Polar Organization Access Tokens and webhook endpoint signing secrets.

## Supported Operations

| Operation | OAT | Webhook Secret |
|---|---:|---:|
| `create` | `POST /v1/organization-access-tokens/` | `PATCH /v1/webhooks/endpoints/{id}/secret` |
| `verify` | `GET /v1/organization-access-tokens/?page=1&limit=1` with the new OAT | `GET /v1/webhooks/endpoints` with the bootstrap OAT |
| `revoke` | `DELETE /v1/organization-access-tokens/{token_id}` | No-op success because reset already invalidates the old secret |
| `list` | `GET /v1/organization-access-tokens/` | `GET /v1/webhooks/endpoints` |

`revoke` is idempotent for OATs. A missing token returns success so repeated revocation attempts are safe. Webhook signing secrets do not have a separate revoke endpoint in Polar; resetting the endpoint secret replaces the old secret immediately.

## Auth Setup

Set a bootstrap Organization Access Token outside the rotated runtime environment:

```bash
export POLAR_BOOTSTRAP_TOKEN="polar_oat_..."
```

The bootstrap token needs `organization_access_tokens:write` for OAT rotation and `webhooks:write` for webhook secret rotation. To verify and list resources, include `organization_access_tokens:read` or `organization_access_tokens:write`, plus `webhooks:read` when rotating webhook secrets. The token must also include every scope you want the newly created OAT to have, because Polar prevents an OAT from minting a token with scopes outside its own scope set.

By default the adapter uses production:

```text
https://api.polar.sh/v1
```

For sandbox usage:

```bash
export POLAR_API_URL="https://sandbox-api.polar.sh/v1"
```

## Metadata Shape

For Organization Access Tokens, `metadata.kind` defaults to `oat`.

```yaml
metadata:
  kind: oat
  organization_id: 1dbfc517-0000-0000-0000-000000000000
  scopes: products:read,products:write,checkouts:read,checkouts:write,orders:read,subscriptions:read,customers:read,webhooks:read,organization_access_tokens:write
  comment: rotate-cli|prod|2026-04-20
  expires_in: P90D
```

For webhook endpoint secrets, use `metadata.kind: webhook`.

```yaml
metadata:
  kind: webhook
  organization_id: 1dbfc517-0000-0000-0000-000000000000
  webhook_endpoint_id: 0a7c90e9-0000-0000-0000-000000000000
```

`metadata.scopes` is a comma-separated list. `metadata.comment`, `metadata.expires_in`, and `metadata.organization_id` are optional for OAT creation unless your bootstrap token type requires an organization id.

## Ownership detection

The adapter preloads the admin token's Polar organizations with `GET /v1/organizations/`, then builds a best-effort webhook signing secret index from `GET /v1/webhooks/endpoints?organization_id={org}&page=1&limit=100` for each readable organization.

For `polar_oat_*`, `polar_at_o_*`, `polar_at_u_*`, and `polar_pat_*` values, ownership is checked by probing `GET /v1/organizations/` with the secret under test and intersecting the returned organization ids with the admin organization set. A match returns `self` with high confidence; a non-empty non-match returns `other` with high confidence; auth, rate limit, provider, or network failures return `unknown`.

For `polar_whs_*` values, ownership uses the preloaded webhook index because webhook secrets are HMAC signing keys and cannot authenticate to Polar. A match inside the admin organization set returns `self` with low confidence; no match returns `unknown` because the secret may belong to an unreadable organization or may have rotated since preload.

## Config Example

```yaml
version: 1

secrets:
  - id: polar-access-token
    adapter: polar
    metadata:
      kind: oat
      organization_id: 1dbfc517-0000-0000-0000-000000000000
      scopes: products:read,products:write,checkouts:read,checkouts:write,orders:read,subscriptions:read,customers:read,webhooks:read,organization_access_tokens:write
      comment: rotate-cli|prod
      expires_in: P90D
    consumers:
      - type: vercel-env
        params:
          project: production-app
          var_name: POLAR_ACCESS_TOKEN

  - id: polar-webhook-secret
    adapter: polar
    metadata:
      kind: webhook
      organization_id: 1dbfc517-0000-0000-0000-000000000000
      webhook_endpoint_id: 0a7c90e9-0000-0000-0000-000000000000
    consumers:
      - type: vercel-env
        params:
          project: production-app
          var_name: POLAR_WEBHOOK_SECRET
```

Polar has no grace period for either credential class. Create the new OAT or reset the webhook secret, propagate it to every consumer, deploy the consumers, and only then revoke the old OAT.
