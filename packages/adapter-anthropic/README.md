# @rotate/adapter-anthropic

Adapter for rotating Anthropic Admin API keys with rotate-cli.

## Supported Operations

- `auth`: reads Anthropic local auth files if present, then falls back to `ANTHROPIC_ADMIN_KEY`.
- `create`: creates a new Anthropic organization API key and returns a populated `Secret`.
- `verify`: makes a real Anthropic Admin API request with the new secret.
- `revoke`: deletes an Anthropic organization API key. `404` is treated as success.
- `list`: lists organization API keys for incident discovery.
- `preloadOwnership`: reads the authenticated org and active API key list for ownership checks.
- `ownedBy`: estimates ownership using the preloaded Admin API key list and sibling env-var signals.

## Auth Setup

Set an Anthropic Admin API key in your shell:

```sh
export ANTHROPIC_ADMIN_KEY="sk-ant-admin-..."
```

The adapter sends:

```txt
x-api-key: <token>
anthropic-version: 2023-06-01
```

The default API base is `https://api.anthropic.com`. For tests or proxies, set `ANTHROPIC_API_URL`.

## Ownership detection

Anthropic standard API keys (`sk-ant-api03-...` and legacy `sk-ant-api-...`) do not expose an organization id through a read-only introspection endpoint. This adapter therefore uses the documented `list-match` strategy:

1. `preloadOwnership()` calls `GET /v1/organizations/me` with the configured admin key.
2. It then calls `GET /v1/organizations/api_keys?limit=1000&status=active` and builds a safe index of key ids, names, workspace ids, timestamps, status, and any partial key hint Anthropic may return.
3. `ownedBy()` checks the suspect key against that preload using partial key hints when available, then env-var name and timestamp correlation when provided by the caller.
4. If no list match is possible, it can fall back to sibling inheritance when another colocated env var has already resolved ownership.

Expected confidence is `medium` for list matches and `low` for sibling inheritance. A non-match against a successfully loaded admin key list returns `other` with low confidence because workspace-scoped admin keys can miss keys in sibling workspaces. Auth failures, rate limits, provider failures, network failures, empty lists, unsupported key formats, and OAuth-subject keys return `unknown` instead of throwing.

`ownedBy()` is read-only. It does not call the Anthropic Messages API or perform a billable liveness probe.

## Config Example

```yaml
version: 1

secrets:
  - id: anthropic-main
    adapter: anthropic
    metadata:
      name: rotate-cli-anthropic-main
      workspace_id: wrk_abc123
    consumers:
      - type: vercel-env
        params:
          project: my-app
          var_name: ANTHROPIC_API_KEY
```
