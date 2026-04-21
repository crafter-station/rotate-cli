# @rotate/adapter-openai

OpenAI adapter for rotate-cli. It creates, verifies, lists, and revokes OpenAI organization admin API keys.

## Supported Operations

| Operation | Supported | API |
|---|---:|---|
| `create` | Yes | `POST /v1/organization/admin_api_keys` |
| `verify` | Yes | `GET /v1/organization/admin_api_keys?limit=1` using the new key |
| `revoke` | Yes | `DELETE /v1/organization/admin_api_keys/{key_id}` |
| `list` | Yes | `GET /v1/organization/admin_api_keys` |

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
