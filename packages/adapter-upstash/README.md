# @rotate/adapter-upstash

Upstash adapter for rotate-cli. This adapter rotates the REST token for an existing Upstash Redis database by calling the Developer API reset-password endpoint.

## Supported Operations

- `auth`: reads `UPSTASH_EMAIL` and `UPSTASH_API_KEY` from the environment.
- `create`: calls `POST /v2/redis/reset-password/{database_id}` and returns the new REST token as the secret value.
- `verify`: calls `GET /v2/redis/database/{database_id}` using Basic auth with the Upstash email and the new REST token.
- `revoke`: no-op that returns `{ ok: true }`. Upstash invalidates the old REST token during reset-password.
- `list`: calls `GET /v2/redis/databases` and returns redacted database-backed secrets.

## Auth Setup

Set both environment variables:

```sh
export UPSTASH_EMAIL="you@example.com"
export UPSTASH_API_KEY="your_upstash_management_api_key"
```

The adapter sends Developer API requests with:

```txt
Authorization: Basic base64(UPSTASH_EMAIL:UPSTASH_API_KEY)
```

## Config Example

```yaml
secrets:
  - id: upstash-main-redis
    adapter: upstash
    metadata:
      database_id: "your-upstash-redis-database-uuid"
    targets:
      - type: local-env
        params:
          path: ".env"
          var_name: "UPSTASH_REDIS_REST_TOKEN"
```

Use `metadata.database_id` for the Redis database UUID. The returned `Secret.value` is the rotated REST token.
