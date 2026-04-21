# @rotate/adapter-fal

fal.ai API key adapter for rotate-cli.

## Supported Operations

- `create`: creates a fal.ai API key with `POST /v1/keys` and returns the one-time `key` value.
- `verify`: verifies the new key with a real `GET /v1/models/usage` request using the new key.
- `revoke`: deletes the old key with `DELETE /v1/keys/:key_id`; `404` is treated as success for idempotency.
- `list`: lists existing keys with redacted values through `GET /v1/keys`.

## Auth Setup

Set an ADMIN-scoped fal.ai key in the environment:

```sh
export FAL_ADMIN_KEY="key_id:key_secret"
```

The rotation credential must be an ADMIN-scoped key. Regular API-scoped keys cannot create, list, or delete keys.

fal.ai admin keys are bootstrapped from the dashboard:

1. Open `https://fal.ai/dashboard/keys`.
2. Create a key with `ADMIN` scope.
3. Copy the full `key_id:key_secret` value immediately.
4. Store it securely and expose it to rotate-cli as `FAL_ADMIN_KEY`.

The adapter sends `Authorization: Key <FAL_ADMIN_KEY>`. The prefix is `Key`, not `Bearer`.

For projects that expose both `FAL_KEY`, `FAL_API_KEY`, and additional aliases, define one consumer entry per target environment variable. rotate-cli consumers handle propagation; this adapter only creates, verifies, lists, and revokes fal.ai keys.

## Config Example

```yaml
version: 1

secrets:
  - id: fal-production
    adapter: fal-ai
    metadata:
      alias: Production
    consumers:
      - type: vercel-env
        params:
          project: app
          var_name: FAL_KEY
      - type: vercel-env
        params:
          project: app
          var_name: FAL_API_KEY
```

Metadata:

- `alias`: optional key alias used in the fal.ai dashboard. Defaults to `rotate-cli <ISO timestamp>`.
- `name`: optional alias fallback if `alias` is not set.

Returned secret metadata:

```ts
{
  key_id: string;
  alias: string;
}
```

`Secret.value` is the full fal.ai `key` response value, usually `key_id:key_secret`. The secret value is shown only once by fal.ai and is not stored in metadata.
