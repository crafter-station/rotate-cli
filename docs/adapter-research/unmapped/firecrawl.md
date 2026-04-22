---
provider: firecrawl
env_vars: [FIRECRAWL_API_KEY]
management_api_base: https://api.firecrawl.dev
auth_method: bearer
rotation_endpoint: no public API
ownership_strategy: none
confidence: high
blockers: [No documented API key create/delete/list endpoints, API docs expose product endpoints that authenticate with a key but do not identify the owning team]
---

## Rotation flow

Firecrawl API docs use `Authorization: Bearer <FIRECRAWL_API_KEY>` for scraping, crawling, extraction, map, and related product APIs. The docs do not expose an API key management surface.

Manual-assist adapter flow:

1. `verify()` calls a cheap authenticated endpoint such as a team usage/credit endpoint if available to the key, or falls back to a harmless API endpoint that does not start a crawl/scrape job.
2. `create()` prompts the user to create a new key in the Firecrawl dashboard and paste it.
3. `revoke()` prompts the user to revoke the old key in the dashboard.

Do not call Firecrawl scrape/crawl/extract endpoints during rotation verification because those create billable or stateful work.

## Ownership detection

No public ownership endpoint found. A valid key proves liveness but not that the current admin account owns the same Firecrawl workspace.

`ownedBy(value, ctx)` should return `unknown` with evidence that Firecrawl has no documented key introspection endpoint.

## preloadOwnership (if applicable)

Not applicable. If Firecrawl later adds team/workspace APIs, preload should enumerate workspaces and key ids, not crawl jobs.

## Gotchas

- Firecrawl jobs are asynchronous and can consume credits; verification must avoid scrape/crawl/job creation.
- API docs use `api.firecrawl.dev` and current SDKs may default to versioned routes behind helper methods.
- MCP tools available in this environment wrap Firecrawl operations but do not expose key management functions.
- Dashboard key creation may reveal the secret only once; rotate-cli should store the pasted value immediately.

## References

- https://docs.firecrawl.dev/api-reference/introduction
- https://docs.firecrawl.dev/features/authentication
- https://docs.firecrawl.dev/api-reference/endpoint/scrape
- https://docs.firecrawl.dev/api-reference/endpoint/crawl
- https://github.com/mendableai/firecrawl
- npm: `@mendable/firecrawl-js`

