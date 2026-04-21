# @rotate/adapter-vercel-kv

Rotate the REST tokens behind legacy Vercel KV env vars (`KV_REST_API_TOKEN`,
`KV_URL`, etc.).

**Note**: Vercel KV was discontinued in Dec 2024 and Vercel auto-migrated
existing stores to Upstash Redis ([ref](https://vercel.com/docs/redis)).
Your old `KV_*` env vars still work but the backend is Upstash. New projects
should use `adapter: upstash` directly.

This adapter exists so `rotate.config.yaml` stays readable for projects that
still have the old KV_* var names. It's a thin wrapper around
[`@rotate/adapter-upstash`](../adapter-upstash/).

## Auth

Needs an Upstash Developer API credential. Accepts either:

| Env var | Alias of |
|---|---|
| `UPSTASH_EMAIL` | — |
| `UPSTASH_API_KEY` | — |
| `VERCEL_KV_EMAIL` | UPSTASH_EMAIL |
| `VERCEL_KV_API_KEY` | UPSTASH_API_KEY |

Grab API credentials from <https://console.upstash.com/account/api>.

## Config example

```yaml
secrets:
  - id: kv-onpe-bot
    adapter: vercel-kv
    metadata:
      database_id: <your-upstash-db-id>
    tags: [non-sensitive]
    consumers:
      - type: vercel-env
        params:
          project: <vercel-project-id>
          team: <vercel-team-id>
          var_name: KV_REST_API_TOKEN
```

## Operations

Everything delegates to [`@rotate/adapter-upstash`](../adapter-upstash/):

- `create`: `POST /v2/redis/reset-password/{database_id}` — rotates the REST
  token in-place without orphaning data.
- `verify`: `GET /v2/redis/database/{database_id}` using the new token.
- `revoke`: no-op (reset-password already invalidates the old token).

## Why a separate package

- Config files stay readable — `adapter: vercel-kv` vs `adapter: upstash`
  makes intent obvious when scanning a large `rotate.config.yaml`.
- Keeps room for future divergence if Vercel switches backing storage.
