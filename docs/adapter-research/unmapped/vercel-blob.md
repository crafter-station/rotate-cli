---
provider: vercel-blob
env_vars: [BLOB_READ_WRITE_TOKEN, BLOB_READ_ONLY_TOKEN, BLOB_STORE_ID, VERCEL_TOKEN]
management_api_base: https://api.vercel.com
auth_method: bearer
rotation_endpoint: no public API
ownership_strategy: format-decode
confidence: medium
blockers: [No documented endpoint to rotate or reset BLOB_READ_WRITE_TOKEN in place, deleting and recreating a store can delete data, Vercel Blob store endpoints are used by the official CLI but absent from public OpenAPI]
---

## Rotation flow

Use `VERCEL_TOKEN` for management auth, not the Blob token under rotation.

Publicly documented SDK operations in `@vercel/blob` only operate on blob objects with `BLOB_READ_WRITE_TOKEN`; they do not create, list, reset, or revoke store credentials. The official Vercel CLI does call internal storage endpoints:

1. `GET /v1/storage/stores` with `accountId` to enumerate stores.
2. `GET /v1/storage/stores/{storeId}` to read one store.
3. `POST /v1/storage/stores/blob` with `{ name, region, access }` to create a new store.
4. `POST /v1/storage/stores/{storeId}/connections` to connect a store to a project and materialize env vars.
5. `DELETE /v1/storage/stores/{storeId}/connections` then `DELETE /v1/storage/stores/blob/{storeId}` to remove a store.

There is no public or CLI-observed credential rotate endpoint. Treat adapter v0 as manual-assist unless Vercel documents or stabilizes a reset endpoint. Do not implement delete-plus-recreate as automatic rotation for existing production stores because it changes resource identity and may affect stored data.

## Ownership detection

`BLOB_READ_WRITE_TOKEN` embeds enough shape for a medium-confidence store lookup. The Vercel CLI derives a store id by splitting the token on `_` and using the fourth segment as `store_${id}`.

`ownedBy(value, ctx)`:

1. Parse candidate token and derive `storeId`.
2. Call `GET /v1/storage/stores/{storeId}` with the admin `VERCEL_TOKEN` and relevant `teamId`/`accountId`.
3. If 200, return `self` with scope `team` or `project`.
4. If 404, return `other` only when preload has a complete list for that Vercel account; otherwise return `unknown`.
5. If parsing fails, fall back to co-located `BLOB_STORE_ID`.

Response shape from CLI source expects `{ store: { id, name, region, ... } }`.

## preloadOwnership (if applicable)

Call `GET /v1/storage/stores` for each reachable Vercel account/team and keep:

```ts
{
  stores: Array<{
    id: string;
    name: string;
    type?: string;
    projectsMetadata?: Array<{ projectId: string; name: string; environments?: string[] }>;
  }>;
}
```

Filter to `type === "blob"` or missing `type`, matching the CLI.

## Gotchas

- The public OpenAPI at `https://openapi.vercel.sh/` does not list Blob store endpoints; the source of truth is currently the official Vercel CLI source.
- Token-derived store id is based on CLI behavior, not documented token format.
- Project connection creates env vars such as `BLOB_READ_WRITE_TOKEN` and `BLOB_STORE_ID`; rotate-cli should prefer updating downstream env vars directly once a manually created token is supplied.
- Private and public Blob stores have different access semantics; preserve access and region metadata if a human recreates the store.
- Vercel API calls generally require `teamId`/account context for team stores.

## References

- https://vercel.com/docs/storage/vercel-blob
- https://vercel.com/docs/vercel-blob/using-blob-sdk
- https://github.com/vercel/vercel/blob/main/packages/cli/src/commands/blob/store-add.ts
- https://github.com/vercel/vercel/blob/main/packages/cli/src/commands/blob/store-list.ts
- https://github.com/vercel/vercel/blob/main/packages/cli/src/commands/blob/store-get.ts
- https://github.com/vercel/vercel/blob/main/packages/cli/src/commands/blob/store-remove.ts
- https://github.com/vercel/vercel/blob/main/packages/cli/src/util/blob/token.ts
- npm: `@vercel/blob`

