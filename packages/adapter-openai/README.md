# @rotate/adapter-openai

OpenAI adapter for rotate-cli. It creates, verifies, lists, and revokes OpenAI organization admin API keys.

## Supported Operations

| Operation | Supported | API |
|---|---:|---|
| `create` | Yes | `POST /v1/organization/admin_api_keys` |
| `verify` | Yes | `GET /v1/organization/admin_api_keys?limit=1` using the new key |
| `revoke` | Yes | `DELETE /v1/organization/admin_api_keys/{key_id}` |
| `list` | Yes | `GET /v1/organization/admin_api_keys` |
| `ownedBy` | Yes | `GET /v1/me` using the candidate key |

`revoke` is idempotent. A missing key returns success so repeated revocation attempts are safe.

## Auth Setup

OpenAI does not provide an official CLI auth store for Admin API keys, so this adapter uses the environment fallback required by rotate-cli:

```bash
export OPENAI_ADMIN_KEY="sk-admin-..."
```

The key must be an OpenAI admin API key created by an organization owner. Standard OpenAI API keys are not sufficient for the Admin API.

## Config Example

```yaml
version: 1

secrets:
  - id: openai-main
    adapter: openai
    metadata:
      name: rotate-cli-openai-main
    consumers:
      - type: vercel-env
        params:
          project: production-app
          var_name: OPENAI_ADMIN_KEY
```

`metadata.name` is optional. If omitted, the adapter creates a timestamped name from the secret id.

## Ownership detection

Ownership detection uses OpenAI API introspection. The adapter calls `GET /v1/me` with the candidate secret as the bearer token, then compares the returned user id and organization ids against the admin ownership context.

Expected confidence is high when `/v1/me` returns a user or organization id that can be matched to the admin context. A known user id match returns `self` with user scope. A known organization id match returns `self` with org scope. If OpenAI returns only organization ids outside the admin context, the adapter returns `other`.

Revoked keys, malformed keys, restricted keys that cannot call `/v1/me`, rate limits, provider errors, network failures, and project-scoped keys that omit organization data return `unknown`. This adapter does not implement `preloadOwnership` because the strategy is one read-only API call per candidate secret.
