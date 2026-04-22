# @rotate/adapter-vercel-blob

Manual-assist adapter for Vercel Blob.

## Auth

The adapter uses `VERCEL_TOKEN` for management authentication against `https://api.vercel.com`. Blob credentials such as `BLOB_READ_WRITE_TOKEN`, `BLOB_READ_ONLY_TOKEN`, and `BLOB_STORE_ID` are the application secrets being rotated, not the management credential.

## Rotation Strategy

Vercel does not document a public API to rotate or reset a Blob store credential in place. The adapter therefore declares `mode: "manual-assist"`:

- `create()` prints dashboard instructions and prompts for a newly created or revealed `BLOB_READ_WRITE_TOKEN`.
- `verify()` performs a cheap management lookup of the token-derived or metadata-provided Blob store id.
- `revoke()` prints cleanup instructions and succeeds only after the user confirms the old token has been removed or invalidated.

The adapter does not delete and recreate Blob stores automatically because that changes resource identity and can affect stored data.

## Ownership

`ownedBy()` derives `store_<id>` from the fourth underscore-delimited segment of `BLOB_READ_WRITE_TOKEN`, matching observed Vercel CLI behavior. It then reads `/v1/storage/stores/{storeId}` with `VERCEL_TOKEN`. If token parsing fails, it falls back to a co-located `BLOB_STORE_ID`.

`preloadOwnership()` best-effort lists Blob stores from the current account and teams through Vercel storage endpoints. A 404 is treated as `other` only when that preload is complete.

## Limitations

The storage store endpoints are used by the official Vercel CLI but are not listed in the public OpenAPI. This adapter intentionally avoids internal create, connect, delete, or credential reset flows until Vercel documents or stabilizes a safe credential rotation endpoint.
