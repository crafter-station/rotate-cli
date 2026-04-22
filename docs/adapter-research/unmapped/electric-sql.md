---
provider: electric-sql
env_vars: [ELECTRIC_SECRET, ELECTRIC_SOURCE_ID, ELECTRIC_API_TOKEN, ELECTRIC_WORKSPACE_ID, ELECTRIC_API_URL]
management_api_base: https://dashboard.electric-sql.cloud/api/rpc
auth_method: bearer
rotation_endpoint: no public API
ownership_strategy: list-match
confidence: medium
blockers: [Cloud CLI uses an ORPC RPC endpoint rather than a documented REST API, no documented in-place service secret rotate endpoint, existing ELECTRIC_SECRET may only be retrievable for a service rather than regenerated]
---

## Rotation flow

Electric Cloud has an official CLI, `@electric-sql/cli`, that manages workspaces, projects, environments, services, and API tokens. The CLI authenticates with `ELECTRIC_API_TOKEN` and talks to `https://dashboard.electric-sql.cloud/api/rpc` using ORPC.

Relevant CLI-backed operations:

1. `auth token create` creates Electric API tokens and returns plaintext once.
2. `auth token list` lists tokens.
3. `auth token revoke <token-id>` revokes an API token.
4. `services create postgres` provisions a Postgres sync service and returns service details.
5. `services get-secret <service-id>` returns service connection credentials.
6. `services delete <service-id>` deletes the service.

For `ELECTRIC_SECRET` and `ELECTRIC_SOURCE_ID`, no public rotate endpoint was found. If the secret belongs to a service, adapter v0 should be manual-assist or create-new-service only when the user explicitly accepts a new service/source id. Do not silently delete and recreate a source because source ids are part of application config.

For Electric API tokens, a separate future `electric-token` adapter is feasible: create token, verify with `auth.whoami`, revoke token by id.

## Ownership detection

Use `ELECTRIC_SOURCE_ID` or service id as the stable ownership key.

`ownedBy(value, ctx, opts)`:

1. Read co-located `ELECTRIC_SOURCE_ID`.
2. Use admin preload service list to find a matching service/source id.
3. If found, return `self` with scope `project`.
4. If the admin preload is complete for all workspaces and no match exists, return `other`; otherwise return `unknown`.

The raw `ELECTRIC_SECRET` should be treated as opaque. Do not attempt format matching on it.

## preloadOwnership (if applicable)

Use the Electric CLI RPC client behavior or shell out to the CLI in a prototype:

```ts
{
  workspaces: Array<{ id: string; name: string }>;
  projects: Array<{ id: string; name: string; workspaceId: string }>;
  environments: Array<{ id: string; name: string; projectId: string }>;
  services: Array<{ id: string; name: string; type: string; environmentId: string }>;
}
```

The CLI docs show `electric projects list --json`, `electric environments list`, `electric services list --environment <id>`, and `electric services get-secret <service-id>`.

## Gotchas

- Browser login sessions expire after 7 days; CI should use `ELECTRIC_API_TOKEN`.
- Token scopes matter: service secret reads require `v2:services:secrets`.
- `ELECTRIC_API_URL` can override the base URL; preserve it for tests and self-hosted/staging.
- Electric Cloud service creation is asynchronous for some service types. Do not assume readiness until the service reports ready.
- Service secrets and API tokens are separate credential classes; do not mix them in one adapter.

## References

- https://electric-sql.com/cloud/cli
- https://dashboard.electric-sql.cloud
- https://www.npmjs.com/package/@electric-sql/cli
- npm: `@electric-sql/cli`

