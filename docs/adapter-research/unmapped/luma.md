---
provider: luma
env_vars: [LUMA_API_KEY]
management_api_base: https://api.lumalabs.ai
auth_method: bearer
rotation_endpoint: no public API
ownership_strategy: none
confidence: high
blockers: [No documented API key management endpoints, no documented organization or key introspection endpoint, generation endpoints may be billable and must not be used for verification]
---

## Rotation flow

Luma AI documents a platform API for media/video generation under `https://api.lumalabs.ai`. Authentication uses bearer API keys. The public docs do not document API key create/list/delete/rotate endpoints.

Manual-assist flow:

1. `verify()` should use a non-generating authenticated endpoint if available, such as listing generations. If no safe endpoint is available, only validate key shape and ask for user confirmation.
2. `create()` asks the user to create a new API key in the Luma dashboard and paste it.
3. `revoke()` asks the user to revoke the old key in the dashboard.

Never call generation endpoints as verification.

## Ownership detection

No public ownership endpoint found. `LUMA_API_KEY` is opaque and product API responses do not prove account ownership.

`ownedBy(value, ctx)` should return `unknown`.

## preloadOwnership (if applicable)

Not applicable until Luma publishes account, project, or key management endpoints.

## Gotchas

- Generation APIs are potentially expensive and asynchronous.
- Some endpoints use pagination for generations/assets; avoid using them for ownership unless a response includes account/project ids in future docs.
- Luma account/team dashboard URLs are not enough for automated rotation.

## References

- https://docs.lumalabs.ai/docs/welcome
- https://docs.lumalabs.ai/reference
- https://lumalabs.ai/api
- npm: `lumaai`

