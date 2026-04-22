---
provider: uploadthing
env_vars: [UPLOADTHING_TOKEN, UPLOADTHING_SECRET, UPLOADTHING_APP_ID]
management_api_base: https://api.uploadthing.com
auth_method: x-api-key
rotation_endpoint: no public API
ownership_strategy: format-decode
confidence: medium
blockers: [No documented API key create/delete/list endpoints, current token format is useful for app id detection but key rotation is dashboard-only]
---

## Rotation flow

UploadThing server SDKs use `UPLOADTHING_TOKEN` or legacy `UPLOADTHING_SECRET` plus `UPLOADTHING_APP_ID`. Public docs cover application use through `uploadthing`, `@uploadthing/react`, and `@uploadthing/server`, but do not document API key management endpoints.

Manual-assist flow:

1. `verify()` instantiates `UTApi` or calls a cheap file listing endpoint using the candidate token.
2. `create()` prompts the user to create or rotate the token in the UploadThing dashboard and paste it.
3. `revoke()` prompts the user to revoke the old token in the dashboard.

Do not upload a test file as verification.

## Ownership detection

Use token/app id decoding and sibling inheritance.

`ownedBy(value, ctx, opts)`:

1. Decode `UPLOADTHING_TOKEN` if it is the modern encoded token format.
2. Extract `appId` when present.
3. Compare with co-located `UPLOADTHING_APP_ID`.
4. If an admin preload ever includes known app ids, compare against that list.
5. Return `self` for app id match, otherwise `unknown`; avoid `other` unless preload is complete.

Legacy `UPLOADTHING_SECRET` is opaque and needs sibling `UPLOADTHING_APP_ID`.

## preloadOwnership (if applicable)

No public app listing endpoint found. A future management API should preload:

```ts
{
  apps: Array<{ id: string; name?: string; teamId?: string }>;
}
```

## Gotchas

- `UPLOADTHING_TOKEN` replaced older separate `UPLOADTHING_SECRET` and `UPLOADTHING_APP_ID` setups; support both.
- Token decode is format-dependent and should be best effort.
- SDK methods may list files and consume rate limits but should not mutate state when used carefully.
- Dashboard-created secrets may only be displayed once.

## References

- https://docs.uploadthing.com/getting-started/appdir
- https://docs.uploadthing.com/api-reference/ut-api
- https://docs.uploadthing.com/concepts/auth-security
- https://uploadthing.com/dashboard
- npm: `uploadthing`
- npm: `@uploadthing/react`

