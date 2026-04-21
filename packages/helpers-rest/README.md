# @rotate/helpers-rest

Shared helper package for simple REST-backed rotate-cli adapters.

## Supported Operations

`defineRestAdapter(spec)` returns an `Adapter` that supports:

- `auth()` by reading provider CLI auth JSON from `~/.<provider>/auth.json`, `~/.<provider>/config.json`, `~/.config/<provider>/auth.json`, or `~/.config/<provider>/config.json`, then falling back to `process.env[authEnvVar]`.
- `create()` with `POST createEndpoint`, bearer auth, and a caller-provided `responseMapper`.
- `verify()` with a real network call to `verifyEndpoint` using the newly created secret value as bearer auth.
- `revoke()` with `DELETE revokeEndpoint`; `404` is treated as success for idempotency.

## Auth Setup

Use an official provider CLI when available so rotate-cli can piggyback on the CLI token. The helper looks for JSON files with one of these token keys: `token`, `access_token`, `apiKey`, or `api_key`.

For development and tests, set the provider token environment variable configured in `authEnvVar`.

```bash
export INTERNAL_TOKEN="provider-token"
```

If neither CLI auth nor the environment variable is available, `auth()` throws a clear auth-unavailable error.

## Config Example

```ts
import { defineRestAdapter } from "@rotate/helpers-rest";

export const internalAdapter = defineRestAdapter({
  name: "internal",
  baseUrl: "https://api.internal.example",
  authEnvVar: "INTERNAL_TOKEN",
  createEndpoint: "/v1/api-keys",
  verifyEndpoint: "/v1/me",
  revokeEndpoint: (secret) => `/v1/api-keys/${secret.metadata.key_id ?? secret.id}`,
  responseMapper: (body, spec) => ({
    id: body.id,
    provider: "internal",
    value: body.secret,
    metadata: { key_id: body.id, secret_id: spec.secretId },
    createdAt: new Date(body.created_at).toISOString(),
  }),
});
```

HTTP status codes are mapped through `makeError`: `401` and `403` become `auth_failed`, `404` becomes `not_found`, `429` becomes retryable `rate_limited`, `5xx` becomes retryable `provider_error`, and other `4xx` responses become non-retryable `provider_error`.
