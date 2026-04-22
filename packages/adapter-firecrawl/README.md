# @rotate/adapter-firecrawl

Manual-assist adapter for Firecrawl.

## Auth

The adapter uses `FIRECRAWL_API_KEY` with bearer authentication against `https://api.firecrawl.dev`.

## Rotation Strategy

Firecrawl documents product APIs for scrape, crawl, map, extract, and account usage, but does not document public API key create, list, delete, or introspection endpoints. The adapter therefore declares `mode: "manual-assist"`:

- `create()` prints dashboard instructions and prompts for a newly created `FIRECRAWL_API_KEY`.
- `verify()` calls `GET /v2/team/credit-usage`, a non-job account endpoint, with the candidate key.
- `revoke()` prints dashboard cleanup instructions and succeeds only after the user confirms the old key has been revoked.

The adapter never calls scrape, crawl, extract, upload, or job creation endpoints during verification.

## Ownership

`ownedBy()` returns `unknown`. Firecrawl liveness proves that a key is valid, but the public docs do not expose a key introspection endpoint that maps the key to a workspace or confirms that the current admin account owns it.

## Limitations

Dashboard-created API keys may reveal the secret only once, so rotate-cli stores the pasted value immediately. If Firecrawl later adds workspace or key management APIs, this adapter can add ownership preload and automated list/revoke support around those documented endpoints.
