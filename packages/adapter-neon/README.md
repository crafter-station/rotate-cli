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

## Ownership detection

The adapter supports `ownedBy()` for Neon API keys and Neon-hosted Postgres connection strings.

- Neon API keys are checked with read-only API introspection. Personal keys are matched through `GET /users/me`; org keys use `GET /organizations`; project-scoped keys fall back to `GET /projects`.
- Neon connection strings are decoded from the hostname endpoint id, such as `ep-cool-darkness-123456`, and matched against a caller-provided cached endpoint-to-project index when available.
- Expected confidence is high for personal and org API keys, high for connection strings with a warm endpoint index, and medium for project-scoped keys.
- Ownership checks never mutate Neon state. If Neon returns an auth error, rate limit, provider error, or the secret shape cannot be recognized, the result is `unknown`.

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
