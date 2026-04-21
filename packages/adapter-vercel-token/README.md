# @rotate/adapter-vercel-token

Adapter for rotating Vercel REST API access tokens.

## Supported Operations

- `create`: creates a Vercel authentication token with `POST /v3/user/tokens` and returns the one-time `bearerToken` as the secret value.
- `verify`: verifies the new token with a real API call to `GET /v2/user`.
- `revoke`: invalidates a token with `DELETE /v3/user/tokens/{tokenId}`. A `404` response is treated as success for idempotency.
- `list`: lists token metadata with `GET /v5/user/tokens` and redacts token values.

## Auth Setup

The adapter prefers Vercel CLI piggyback auth. Run:

```sh
vercel login
```

It checks these Vercel CLI auth files:

- macOS: `~/Library/Application Support/com.vercel.cli/auth.json`
- Linux: `~/.local/share/com.vercel.cli/auth.json`
- Fallback: `~/.config/vercel/auth.json`

For development and CI, set:

```sh
export VERCEL_TOKEN=...
```

## Config Example

```yaml
version: 1

secrets:
  - id: vercel-api-main
    adapter: vercel-token
    metadata:
      team_id: team_abc123
      name: rotate-cli-vercel-api-main
      expires_at: "1776643200000"
    consumers:
      - type: vercel-env
        params:
          project: my-app
          var_name: VERCEL_TOKEN
```

`metadata.team_id`, `metadata.team_slug`, `metadata.name`, and `metadata.expires_at` are optional. `expires_at` must be a millisecond timestamp string accepted by the Vercel API.

## Ownership detection

`ownedBy()` uses API introspection with `GET /v5/user/tokens/current`, authenticated with the secret value being classified. Vercel returns the token scope directly, so the adapter can distinguish user-scoped tokens from team-scoped tokens without mutating provider state.

For team-scoped tokens, the adapter compares the returned team scope with the admin token's `GET /v2/teams` memberships. Team membership returns `verdict: "self"` with high confidence; an absent membership returns `verdict: "other"` with high confidence. `adminCanBill` is true only for Vercel `OWNER` or `BILLING` roles.

For user-scoped tokens, the adapter compares `GET /v2/user` for the secret token against the admin token's `GET /v2/user` identity. Matching users return `verdict: "self"` with high confidence; different users return `verdict: "other"` with high confidence.

If token introspection fails with `401` or `403`, the adapter returns `verdict: "unknown"` because the token may be inactive, revoked, or unavailable for introspection. Rate limits, provider errors, and network failures also degrade to `unknown` instead of aborting rotation.
