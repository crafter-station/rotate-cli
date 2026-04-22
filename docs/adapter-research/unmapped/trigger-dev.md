---
provider: trigger.dev
env_vars: [TRIGGER_SECRET_KEY, TRIGGER_ACCESS_TOKEN]
management_api_base: https://api.trigger.dev
auth_method: bearer
rotation_endpoint: no public API
ownership_strategy: none
confidence: medium
blockers: [No documented public API to create or revoke project secret keys, project secret key ownership is not introspectable from public docs, CLI uses dashboard authentication and project references rather than key management endpoints]
---

## Rotation flow

Trigger.dev v3 uses `TRIGGER_SECRET_KEY` at runtime and personal/dashboard auth for CLI operations. Public docs cover creating and copying API keys from the dashboard and using `trigger.dev` CLI commands, but they do not document a management endpoint for creating, rotating, or revoking project secret keys.

Recommended v0 adapter shape is manual-assist:

1. Verify candidate key with the cheapest Trigger.dev API or SDK call available to the project. Do not enqueue runs as verification.
2. Ask the user to create a replacement secret key in the Trigger.dev dashboard.
3. Accept the pasted value as the new `Secret`.
4. After propagation and verification, ask the user to revoke the old key in the dashboard.

Do not execute any job or environment mutation as part of verification.

## Ownership detection

No robust public ownership strategy found for `TRIGGER_SECRET_KEY`.

`ownedBy(value, ctx)` should return `unknown` unless a future API returns project or organization identity for the key. Co-located variables such as Trigger project refs can help humans choose the right dashboard location but do not prove ownership.

## preloadOwnership (if applicable)

Not applicable with public docs. If a future CLI/API endpoint lists organizations/projects for a personal access token, preload should return:

```ts
{
  organizations: Array<{ id: string; slug?: string; role?: string }>;
  projects: Array<{ id: string; ref?: string; slug?: string; organizationId?: string }>;
}
```

## Gotchas

- `TRIGGER_SECRET_KEY` is a runtime credential, while CLI login tokens are a different credential class.
- Trigger.dev has project refs and environment concepts; preserve environment metadata if the user supplies it.
- Treat dashboard-only rotation as Tier 2. The adapter can still be valuable for detection and guided rotation, but it cannot be fully automated from current public docs.

## References

- https://trigger.dev/docs
- https://trigger.dev/docs/apikeys
- https://trigger.dev/docs/cli
- https://trigger.dev/docs/config/config-file
- npm: `@trigger.dev/sdk`
- npm: `trigger.dev`

