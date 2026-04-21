# @rotate/adapter-ai-gateway

Adapter for rotating Vercel AI Gateway credentials in rotate-cli.

## Provider

`vercel-ai-gateway`

## Supported Operations

- `create`: creates a Vercel auth token using the Vercel REST API and returns it as an AI Gateway secret value.
- `verify`: verifies the new token with a real `GET /v2/user` Vercel API request using the newly created secret value.
- `revoke`: deletes the Vercel auth token. A `404` response is treated as success so revoke is idempotent.
- `list`: lists Vercel auth tokens through `GET /v5/user/tokens`, returning redacted secret values.

## AI Gateway Scope

Vercel AI Gateway API keys are currently managed from the Vercel dashboard. This adapter is a v0.1 thin wrapper over Vercel access tokens because AI Gateway keys are Vercel-managed credentials and there is no documented dedicated public AI Gateway key-management REST endpoint.

The created token can be propagated as `AI_GATEWAY_API_KEY` for AI Gateway usage. Users who need literal AI Gateway project-scoped keys should use a future adapter if Vercel exposes a dedicated API for those keys.

## Auth Setup

The adapter authenticates to Vercel using the Vercel CLI auth token, then falls back to `VERCEL_TOKEN`.

Vercel CLI token locations:

- macOS: `~/Library/Application Support/com.vercel.cli/auth.json`
- macOS/Linux fallback: `~/.local/share/com.vercel.cli/auth.json`
- fallback: `~/.config/vercel/auth.json`

For local testing:

```sh
export VERCEL_TOKEN="your-vercel-token"
```

## Metadata

Optional metadata:

- `teamId` or `team_id`: Vercel team ID.
- `teamSlug` or `team_slug`: Vercel team slug.
- `name`: token name. Defaults to `ai-gateway-rotated-<timestamp>`.
- `expiresAt` or `expires_at`: expiration timestamp in milliseconds.

Returned secret metadata includes:

- `token_id`: Vercel token ID.
- `name`: Vercel token name.
- `type`: Vercel token type.
- `teamId` and `team_id`, when provided.
- `teamSlug` and `team_slug`, when provided.

## Config Example

```yaml
version: 1
secrets:
  - id: ai-gateway
    adapter: vercel-ai-gateway
    metadata:
      teamId: team_123
      name: ai-gateway-rotated-production
    consumers:
      - type: vercel-env
        params:
          project: prj_123
          var_name: AI_GATEWAY_API_KEY
          team: team_123
```
