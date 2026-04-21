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

## Ownership detection

The adapter implements `preloadOwnership()` and `ownedBy()` for Upstash Redis REST tokens and Vercel KV aliases. Preload calls `GET /v2/redis/databases` once with the configured Upstash management credentials and builds a warm index by database endpoint plus SHA-256 hashes of both `rest_token` and `read_only_rest_token`.

`ownedBy()` checks co-located REST URL variables first (`UPSTASH_REDIS_REST_URL`, `KV_REST_API_URL`) by decoding the `https://{slug}.upstash.io` endpoint and matching it against the warm index. It also supports Redis protocol URLs from `KV_URL` and `REDIS_URL`. If no URL is available, it hashes the candidate REST token and checks the token index.

Expected confidence is high when an Upstash endpoint matches the admin index, high when a REST token hash matches, medium unknown when a token does not match, and low unknown when the ownership index cannot be built. Ownership checks are read-only and degrade to `unknown` on auth, network, rate-limit, or provider failures.
