# @rotate/adapter-neon-connection

Neon Postgres connection string adapter for rotate-cli.

This adapter rotates a Neon branch role password and returns a `DATABASE_URL`-style connection string.

## Supported Operations

- `create`: resets the Neon branch role password with `POST /projects/{project_id}/branches/{branch_id}/roles/{role_name}/reset_password`, then returns `postgresql://{role}:{password}@{host}/{database}?sslmode=require`.
- `verify`: checks the Neon API key and project with `GET /projects/{project_id}`.
- `revoke`: no-op success. Neon does not expose per-password revocation; `reset_password` invalidates the previous role password during `create`.

`list` is not implemented.

## Auth Setup

Set a Neon API key in the environment:

```sh
export NEON_API_KEY="napi_..."
```

The adapter uses `NEON_API_KEY` against `https://console.neon.tech/api/v2`. For tests or local API overrides, set `NEON_API_URL`.

## Verification Limitation

This package has no database driver dependency, so `verify` cannot open a Postgres connection with the new URL. It makes a real Neon API call to confirm that the API key and project are still valid. The strongest post-rotation signal should come from a consumer-side health check in the application that uses the new `DATABASE_URL`.

## Ownership detection

`ownedBy()` uses format-decode ownership detection for Neon Postgres connection strings. It extracts the globally unique `ep-...` endpoint id from the connection hostname, strips the optional `-pooler` suffix, and checks that id against a warm `endpointToProject` reverse index supplied in `opts.preload`.

The check makes zero provider calls and never logs or returns the connection string password. A hit in an owned org returns `verdict: "self"` with high confidence; a hit outside the known org set returns `verdict: "other"` with high confidence; a malformed string, missing index, or endpoint miss returns `verdict: "unknown"` for human review.

`preloadOwnership()` is intentionally not implemented for this adapter because the ownership strategy is `format-decode`, not `list-match`.

## Config Example

```yaml
version: 1

secrets:
  - id: database-url
    adapter: neon-connection
    metadata:
      project_id: prj_abc123
      branch_id: br_main
      role_name: app
      database_name: main
      host: ep-example.us-east-1.aws.neon.tech
      pooled_host: ep-example-pooler.us-east-1.aws.neon.tech
      unpooled_host: ep-example.us-east-1.aws.neon.tech
    consumers:
      - type: vercel-env
        params:
          project: my-app
          var_name: DATABASE_URL
```

`branch_id` defaults to `main` if omitted. When `pooled_host` or `unpooled_host` is provided, the returned secret metadata also includes `pooled_connection_string` or `unpooled_connection_string`.
