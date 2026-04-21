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

## Ownership detection

`ownedBy()` uses Resend's domain list as a team fingerprint because Resend API keys do not expose a parseable tenant marker and `GET /api-keys` does not return token fragments.

`preloadOwnership()` calls `GET /domains` with the admin key and caches the admin team's domain IDs. For each candidate `re_...` key, `ownedBy()` calls `GET /domains` with the candidate key:

- if every returned domain ID is in the admin fingerprint, the verdict is `self`
- if no returned domain IDs are in the admin fingerprint, the verdict is `other`
- if the candidate key cannot list domains, is revoked, is rate limited, or the provider is unavailable, the verdict is `unknown`
- if a send-only key returns `403`, ownership can fall back to sibling env-var inference when the caller provides that signal

The primary strategy is `list-match` with `medium` confidence. Sibling inference uses `low` confidence because Resend send-only keys cannot be verified through a read-only ownership endpoint.

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
