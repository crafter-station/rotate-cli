# @rotate/adapter-elevenlabs

ElevenLabs service-account API key rotation for rotate-cli.

## Supported Operations

- `auth`: reads `ELEVENLABS_ADMIN_KEY` from the environment.
- `create`: creates a new service-account API key with `POST /v1/service-accounts/{service_account_user_id}/api-keys`.
- `verify`: verifies the new key with `GET /v1/user` using the new key in the `xi-api-key` header.
- `revoke`: deletes a service-account API key with `DELETE /v1/service-accounts/{service_account_user_id}/api-keys/{key_id}`. A 404 is treated as success.
- `list`: lists keys for a service account with `GET /v1/service-accounts/{service_account_user_id}/api-keys`.

## Auth Setup

Set an ElevenLabs admin workspace key:

```sh
export ELEVENLABS_ADMIN_KEY="..."
```

The key must belong to a workspace admin on a multi-seat workspace with service-account access. ElevenLabs personal single-seat API keys cannot use the service-account key management endpoints. If the API returns 403, rotate-cli reports an auth error that the operation requires a multi-seat workspace.

By default the adapter calls `https://api.elevenlabs.io`. For data-residency workspaces or tests, override it:

```sh
export ELEVENLABS_API_URL="https://api.eu.elevenlabs.io"
```

## Required Metadata

`service_account_user_id` is required. It is the `sa_...` service-account user id from ElevenLabs. You can find it from the service-account listing endpoint or from the service-account dashboard URL.

Optional metadata:

- `name`: key name. Defaults to `rotate-cli-managed-<iso timestamp>`.
- `permissions`: `all`, a JSON string array, or a comma-separated list such as `text_to_speech,speech_to_text`.
- `character_limit`: monthly character cap to set on the new key.
- `previous_key_id`: old key id to carry in metadata until explicit revoke.

## Metadata Shape

The adapter stores provider metadata as strings to match `@rotate/core/types`:

```ts
{
  provider: "elevenlabs",
  mode: "api",
  service_account_user_id: "sa_...",
  key_id: "key_...",
  name: "rotate-cli-managed-2026-04-21T00:00:00.000Z",
  permissions: "all",
  character_limit: "1000000",
  hint: "abcd",
  created_at_unix: "1776729600",
  rotated_at: "2026-04-21T00:00:00.000Z",
  previous_key_id: "key_old"
}
```

`hint`, `created_at_unix`, and disabled/count/hash fields are populated by `list()` when ElevenLabs returns them. The full secret value is only returned by `create()` and is redacted in `list()`.

## Ownership detection

`ownedBy()` uses one read-only API introspection call: `GET /v1/user` with the candidate key in the `xi-api-key` header. The response includes a `user_id`, seat type, and subscription tier, but ElevenLabs does not return a stable workspace id.

The adapter compares the returned `user_id` against pre-seeded ownership context such as `knownUserIds` on the auth context or ownership preload passed by the caller. A match returns `self` with medium confidence. A miss returns `other` with medium confidence when ownership context exists. If the candidate key is rejected, the provider is unavailable, the response is malformed, or no pre-seeded context is available, the adapter returns `unknown` instead of throwing.

For workspace service-account keys, a matching subscription tier plus a non-admin seat is treated as ambiguous when the `user_id` was not pre-seeded, so the result is `unknown`. This avoids claiming ownership from tier alone because different ElevenLabs workspaces can share the same plan tier.

## Config Example

```yaml
secrets:
  - id: elevenlabs/main
    adapter: elevenlabs
    metadata:
      service_account_user_id: sa_123
      permissions: all
      character_limit: "1000000"
```

Rotation creates the new key first and does not revoke the old key. After consumers are updated and verification succeeds, call revoke for the previous key id.
