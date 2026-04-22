---
provider: mistral
env_vars: [MISTRAL_API_KEY]
management_api_base: https://api.mistral.ai
auth_method: bearer
rotation_endpoint: no public API
ownership_strategy: none
confidence: high
blockers: [No documented public API key create/list/delete endpoints, documented key creation is workspace console flow, no documented key introspection endpoint]
---

## Rotation flow

Mistral documents API usage with `Authorization: Bearer <MISTRAL_API_KEY>` against `https://api.mistral.ai/v1`. Public help docs describe creating API keys in a workspace from the console, but no API key management endpoint was found in the public API reference.

Manual-assist flow:

1. `verify()` calls `GET /v1/models` with the candidate key.
2. `create()` sends the user to the Mistral console workspace API key flow and asks them to paste the new key.
3. `revoke()` asks the user to delete or revoke the old key in the console.

## Ownership detection

No public key ownership endpoint found. `GET /v1/models` verifies that the key works but returns model data, not workspace identity.

`ownedBy(value, ctx)` should return `unknown`.

## preloadOwnership (if applicable)

Not applicable until Mistral publishes workspace/key management endpoints.

## Gotchas

- Workspaces matter for billing, but workspace identity is not exposed through the common model endpoint.
- Keep verification to `GET /v1/models`; avoid chat/completion calls.
- Mistral SDKs support inference and agents APIs, not key lifecycle management.

## References

- https://docs.mistral.ai/api/
- https://docs.mistral.ai/getting-started/quickstart/
- https://help.mistral.ai/en/articles/347464-how-do-i-create-api-keys-within-a-workspace
- https://console.mistral.ai/api-keys
- npm: `@mistralai/mistralai`

