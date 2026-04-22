---
provider: kapso
env_vars: [KAPSO_API_KEY, KAPSO_WEBHOOK_SECRET]
management_api_base: https://api.kapso.io
auth_method: x-api-key
rotation_endpoint: no public API
ownership_strategy: api-introspection
confidence: low
blockers: [No Kapso MCP tools are available in this session despite task context, public docs/search results did not reveal API key or webhook secret lifecycle endpoints, ownership strategy depends on project/account identifiers returned by existing read endpoints]
---

## Rotation flow

Kapso appears to expose a platform API authenticated by `KAPSO_API_KEY`, but public search did not surface a documented API key management endpoint or webhook secret rotation endpoint.

Recommended v0 adapter is manual-assist:

1. `verify()` calls a read-only account/project endpoint if documented internally, or a harmless list endpoint.
2. `create()` asks the user to generate a new API key in Kapso and paste it.
3. `revoke()` asks the user to revoke the old API key in Kapso.
4. `KAPSO_WEBHOOK_SECRET` should be treated as a separate manual secret unless Kapso exposes webhook endpoint secret rotation.

## Ownership detection

Likely feasible through API introspection if Kapso read endpoints return account/project ids.

`ownedBy(value, ctx)`:

1. Call a read-only `whoami`, organization, project, or account endpoint with the candidate key.
2. Compare returned org/project id with admin preload.
3. Return `self` for exact id match, `other` only if preload is complete and candidate returned a different id, otherwise `unknown`.

Because public docs were not available, keep confidence low and do not implement until an internal Kapso API contract is available.

## preloadOwnership (if applicable)

Expected shape:

```ts
{
  organizations: Array<{ id: string; slug?: string; role?: string }>;
  projects: Array<{ id: string; organizationId?: string; name?: string }>;
  webhooks: Array<{ id: string; projectId?: string; url?: string }>;
}
```

## Gotchas

- Task context mentions `mcp__kapso__*`, but no such tools are installed in this session.
- Webhook signing secrets may be endpoint-specific rather than account-wide.
- Internal platform ownership should be confirmed with Hunter before building an adapter.

## References

- https://kapso.io
- https://docs.kapso.ai
- Internal follow-up needed: Kapso API docs for account/project/key/webhook endpoints

