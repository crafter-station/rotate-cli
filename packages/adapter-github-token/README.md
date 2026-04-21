# @rotate/adapter-github-token

Adapter for rotating GitHub App installation access tokens.

## Supported Operations

- `create`: creates a GitHub App installation access token with `POST /app/installations/{installation_id}/access_tokens`.
- `verify`: verifies the new token with a real GitHub API call to `GET /installation/repositories`.
- `revoke`: revokes the installation access token with `DELETE /installation/token`; `404` is treated as success.
- `list`: returns installation metadata for the configured `installation_id`. GitHub does not list active installation access token values.

## Auth Setup

The adapter checks auth in this order:

1. GitHub CLI piggyback via `gh auth token`.
2. `GITHUB_TOKEN` environment variable.

The create endpoint requires a GitHub App JWT as the bearer token. `gh auth token` commonly returns a user token, which can verify account access but cannot mint installation access tokens unless it is replaced by a valid app JWT in the runtime environment. For non-interactive rotation, set `GITHUB_TOKEN` to a short-lived GitHub App JWT generated outside rotate-cli.

GitHub does not provide a general REST API to mint new personal access tokens. This adapter targets GitHub App installation access tokens and documents that PAT rotation is unsupported.

## Ownership detection

`ownedBy()` uses GitHub token prefix decoding plus one read-only API introspection call. User-scoped tokens (`ghp_`, `github_pat_`, `gho_`, and `ghu_`) are checked with `GET /user`. Installation tokens (`ghs_`) are checked with `GET /installation/repositories?per_page=1` and reconciled against any admin installation data supplied in `opts.preload`.

Expected confidence is high when GitHub returns an owner and the caller provides admin identity or installation context. Revoked, expired, refresh-only, rate-limited, or unrecognized tokens return `unknown` instead of throwing. The adapter does not implement `preloadOwnership()` because the documented strategy is O(1) API introspection rather than list matching.

## Config Example

```yaml
version: 1

secrets:
  - id: github-app-main
    adapter: github
    metadata:
      installation_id: "12345678"
      repositories: "crafter-station/rotate-cli"
      permissions: "contents:read,metadata:read"
    consumers:
      - type: vercel-env
        params:
          project: rotate-cli
          var_name: GITHUB_APP_INSTALLATION_TOKEN
```

Optional metadata:

- `repositories`: comma-separated repository names, such as `owner/repo,owner/other`.
- `repository_ids`: comma-separated numeric repository IDs.
- `permissions`: comma-separated `permission:level` entries, such as `contents:read,issues:write`.
