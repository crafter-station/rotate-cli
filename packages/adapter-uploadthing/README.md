# @rotate/adapter-uploadthing

UploadThing manual-assist adapter for rotate-cli.

## Supported Operations

- `create`: guides the user to create or rotate a token in the UploadThing dashboard, then stores the pasted value.
- `verify`: checks the candidate token with a non-mutating authenticated UploadThing API request.
- `revoke`: guides the user to revoke the old token in the UploadThing dashboard and records success after confirmation.

UploadThing does not document public API key create, delete, or list endpoints, so this adapter runs in `manual-assist` mode.

## Auth Setup

Use the modern token when available:

```sh
export UPLOADTHING_TOKEN="..."
```

Legacy setups are also recognized:

```sh
export UPLOADTHING_SECRET="..."
export UPLOADTHING_APP_ID="..."
```

`UPLOADTHING_TOKEN` is preferred over `UPLOADTHING_SECRET` when both are present.

## Rotation Strategy

Create and revoke are dashboard-only:

1. Open `https://uploadthing.com/dashboard`.
2. Select the app that owns the secret.
3. Create or rotate the server token and paste the newly displayed value into rotate-cli.
4. After consumers are updated, revoke the old token in the dashboard and confirm in rotate-cli.

The adapter never uploads a test file for verification.

## Ownership Detection

`ownedBy()` best-effort decodes modern `UPLOADTHING_TOKEN` values and compares the embedded app id with co-located `UPLOADTHING_APP_ID`. If a future preload contains UploadThing apps, the same decoded app id can be matched against that list.

Legacy `UPLOADTHING_SECRET` values are opaque, so ownership can only be inferred from a co-located `UPLOADTHING_APP_ID` and returns low confidence. Without an app id signal, ownership is `unknown`.

## Limitations

- Public UploadThing key-management endpoints are not documented.
- Dashboard-created secrets may only be displayed once.
- Token decoding is format-dependent and best effort.
