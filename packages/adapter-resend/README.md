# @rotate/adapter-resend

Resend API key adapter for rotate-cli.

## Supported Operations

- `create`: creates a Resend API key with `POST /api-keys` and returns the one-time `token`.
- `verify`: verifies the new key with a real `GET /api-keys` request using the new key as bearer auth.
- `revoke`: deletes the old key with `DELETE /api-keys/:api_key_id`; `404` is treated as success for idempotency.
- `list`: lists existing API keys with redacted values.

## Auth Setup

Set a full-access Resend API key in the environment:

```sh
export RESEND_API_KEY="re_xxxxxxxxx"
```

The key used for rotation must be able to create, list, and delete API keys.

## Config Example

```yaml
version: 1

secrets:
  - id: resend-production
    adapter: resend
    metadata:
      name: Production
      permission: full_access
    consumers:
      - type: vercel-env
        params:
          project: app
          var_name: RESEND_API_KEY
```

Metadata:

- `name`: optional API key name. Defaults to `rotate-cli-<secretId>-<timestamp>` and is truncated to Resend's 50 character limit.
- `permission`: optional, either `full_access` or `sending_access`. Use `full_access` when rotate-cli must verify the new key through `GET /api-keys`.
