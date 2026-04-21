# @rotate/adapter-turso

Turso adapter for rotate-cli. It rotates Turso libSQL database auth tokens and returns a fresh `TURSO_AUTH_TOKEN` value.

## Supported Operations

| Operation | Supported | API |
|---|---:|---|
| `create` | Yes | `POST /v1/organizations/{organization}/databases/{database}/auth/rotate`, then `POST /v1/organizations/{organization}/databases/{database}/auth/tokens` |
| `verify` | Yes | `POST https://{database}-{organization}.turso.io/v2/pipeline` using the new DB token |
| `revoke` | Yes | No-op, returns success |
| `list` | No | Turso does not expose a DB auth token list endpoint for this adapter |
| `ownedBy` | Yes | Format-decodes `libsql://{database}-{organization}.turso.io` and compares the organization slug to the admin token's organizations |

`create` invalidates all existing DB auth tokens first, then mints the replacement token. This order matters because Turso's rotate endpoint invalidates every outstanding DB token, including one created moments earlier.

`revoke` is intentionally a no-op. Turso DB auth token invalidation is database-wide, and `create` already performs that invalidation before minting the new token. Repeated revocation attempts are safe and always return success.

## Auth Setup

Set a Turso Platform API token in the environment:

```bash
export TURSO_PLATFORM_TOKEN="eyJ..."
```

The token must be a Turso Platform API token with access to the target organization. For blast-radius containment, mint it scoped to the organization:

```bash
turso auth api-tokens mint rotate-cli --org acme
```

CLI piggyback support is planned for v0.2. In v0.1 this adapter is env-only so CI usage stays explicit and reproducible.

## Metadata

Required:

| Field | Description |
|---|---|
| `organization` | Turso organization slug |
| `database` | Turso database name |

Optional:

| Field | Default | Description |
|---|---|---|
| `expiration` | `never` | Turso token expiration query value, such as `7d` or `2w1d30m` |
| `authorization` | `full-access` | Turso token authorization, either `full-access` or `read-only` |
| `hostname` | `{database}-{organization}.turso.io` | Override for the libSQL HTTP verification hostname |

The returned `Secret.value` is the JWT returned by Turso's `auth/tokens` endpoint. Consumers that need a connection string with `authToken` should build that value downstream.

## Ownership Detection

Ownership detection uses the Turso connection URL, because `libsql://{database}-{organization}.turso.io` encodes the organization slug in the hostname. The adapter parses the hostname, splits on the last `-` before `.turso.io`, and compares that organization slug against the organizations visible to the configured `TURSO_PLATFORM_TOKEN`.

When `ownedBy()` receives a database auth token, it looks for a co-located `TURSO_DATABASE_URL` or `DATABASE_URL` and uses that URL for the ownership decision. This returns `self` or `other` with high confidence when the URL is Turso-managed. A loose `TURSO_AUTH_TOKEN` without its paired URL returns `unknown`, because Turso DB auth JWTs do not encode database or organization identity.

`preloadOwnership()` warms the admin organization list and a database hostname index with read-only Turso API calls. Later ownership checks can use the preload without additional network calls.

## Config Example

```yaml
version: 1

secrets:
  - id: turso-main
    adapter: turso
    metadata:
      organization: acme
      database: main
      expiration: never
      authorization: full-access
    consumers:
      - type: vercel-env
        params:
          project: production-app
          var_name: TURSO_AUTH_TOKEN
```
