# @rotate/adapter-neon

Neon API key adapter for rotate-cli.

## Supported Operations

- `create`: creates a project-scoped Neon API key with `POST /projects/{project_id}/api_keys`.
- `verify`: checks the new key with `GET /users/me`.
- `revoke`: revokes the key with `DELETE /projects/{project_id}/api_keys/{key_id}`. A `404` is treated as success so revoke is idempotent.

## Auth Setup

Set a Neon API key in the environment:

```sh
export NEON_API_KEY="napi_..."
```

The adapter does not use CLI piggyback auth.

## Config Example

```yaml
version: 1

secrets:
  - id: neon-main
    adapter: neon
    metadata:
      project_id: prj_abc123
    consumers:
      - type: vercel-env
        params:
          project: my-app
          var_name: NEON_API_KEY
```
