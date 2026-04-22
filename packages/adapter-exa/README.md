# @rotate/adapter-exa

Auto adapter for Exa API key rotation.

## Auth

Set `EXA_API_KEY` to an Exa service/admin API key that can access the Team Management API.

The adapter authenticates against `https://admin-api.exa.ai/team-management` with the `x-api-key` header.

## Rotation

- `create()` calls `POST /api-keys` with a generated or provided name and optional `metadata.rateLimit`.
- `verify()` calls `GET /api-keys` with the newly created key, avoiding paid search endpoints.
- `revoke()` calls `DELETE /api-keys/{id}` using the stored key id.
- `list()` calls `GET /api-keys` and maps returned metadata to redacted rotate-cli secrets.

## Ownership

Ownership uses API introspection through the Team Management API. It compares returned `teamId` values when available and falls back to API-key inventory overlap when Exa omits team ids from list responses.

## Limitations

Exa's published create response currently documents key metadata but not a plaintext secret value. Automated rotation only succeeds if the API returns the new plaintext key once. If Exa returns metadata only, `create()` returns `unsupported` so the rotation does not proceed with an unusable secret.
