# @rotate/adapter-supabase

Supabase adapter for rotate-cli. It creates, verifies, lists, and revokes Supabase project API keys through the Supabase Management API.

## Supported Operations

| Operation | Support | Endpoint |
|---|---:|---|
| `auth()` | Yes | `SUPABASE_ACCESS_TOKEN` |
| `create()` | Yes | `POST /v1/projects/{ref}/api-keys?reveal=true` |
| `verify()` | Yes | `GET https://{project_ref}.supabase.co/rest/v1/` with the new key as `apikey` |
| `revoke()` | Yes | `DELETE /v1/projects/{ref}/api-keys/{id}` |
| `list()` | Yes | `GET /v1/projects/{ref}/api-keys?reveal=false` |

`revoke()` is idempotent. A Supabase `404` during revoke is treated as success.

## Auth Setup

Supabase CLI auth is session-based, so this adapter does not piggyback on the CLI. Create a Supabase personal access token and provide it as:

```bash
export SUPABASE_ACCESS_TOKEN="sbp_..."
```

The token must be allowed to manage API keys for the target project. Fine-grained tokens need API Gateway key read/write permissions.

## Config Example

```yaml
version: 1

secrets:
  - id: supabase-main
    adapter: supabase
    metadata:
      project_ref: abcdefghijklmnop
      type: secret
    consumers:
      - type: vercel-env
        params:
          project: my-app
          var_name: SUPABASE_SECRET_KEY
```

Optional metadata:

| Key | Purpose |
|---|---|
| `type` | Supabase API key type. Defaults to `secret`. |
| `name` | API key display name. Defaults to `rotate-cli-{timestamp}`. |
| `project_url` | Override project URL used by `verify()`. Defaults to `https://{project_ref}.supabase.co`. |

The created `Secret` includes `metadata.project_ref`, `metadata.key_id`, `metadata.type`, `metadata.name`, and `metadata.prefix` when Supabase returns them.
