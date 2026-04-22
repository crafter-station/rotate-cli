---
provider: exa
env_vars: [EXA_API_KEY]
management_api_base: https://admin-api.exa.ai
auth_method: x-api-key
rotation_endpoint: POST /team-management/api-keys
ownership_strategy: api-introspection
confidence: high
blockers: [Create API key response in docs should be verified to ensure plaintext key is returned once, management API requires an admin API key distinct from normal search usage]
---

## Rotation flow

Exa has a documented Team Management API under `https://admin-api.exa.ai`. It authenticates with an Exa API key in the `x-api-key` header and includes API key management endpoints.

Expected adapter flow:

1. `create()` calls `POST /team-management/api-keys` with a name and optional metadata/limits supported by the docs.
2. Store returned key id and plaintext key if the response includes it. If the response only returns metadata, block automated rotation and downgrade to manual-assist.
3. `verify()` calls a cheap authenticated endpoint with the new key, such as team info or a no-cost API-key read if available. Avoid paid search calls for verification.
4. `revoke()` calls the documented delete/revoke API key endpoint for the stored key id.
5. `list()` calls the documented list API keys endpoint and maps redacted keys to `Secret` metadata.

## Ownership detection

Use API introspection.

`ownedBy(value, ctx)`:

1. Call a team info or current-key endpoint with the candidate `EXA_API_KEY`.
2. Compare returned team id with the admin key's team id.
3. Return `self` for exact team id match.
4. Return `other` for a different team id.
5. Return `unknown` on 401/403 or if the key lacks team-management access.

If Exa does not allow normal search keys to call team-management endpoints, ownership for non-admin keys may need `none` or a paid search liveness probe only.

## preloadOwnership (if applicable)

Use team management list endpoints:

```ts
{
  team: { id: string; name?: string };
  apiKeys: Array<{ id: string; name?: string; createdAt?: string; lastUsedAt?: string | null }>;
}
```

## Gotchas

- Exa has separate product APIs and `admin-api.exa.ai`; use the admin base for key lifecycle.
- Confirm whether `POST /team-management/api-keys` returns plaintext secret value. Rotate-cli `create()` cannot succeed without the new secret.
- Admin API keys may need elevated team permissions.
- Avoid using search endpoints for ownership; they can incur usage.

## References

- https://docs.exa.ai/reference/team-management/create-api-key
- https://docs.exa.ai/reference/team-management/list-api-keys
- https://docs.exa.ai/reference/team-management/delete-api-key
- https://docs.exa.ai/reference/team-management/get-team
- https://docs.exa.ai/reference/getting-started
- npm: `exa-js`

