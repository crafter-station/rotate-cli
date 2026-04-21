# @rotate/adapter-anthropic

Adapter for rotating Anthropic Admin API keys with rotate-cli.

## Supported Operations

- `auth`: reads Anthropic local auth files if present, then falls back to `ANTHROPIC_ADMIN_KEY`.
- `create`: creates a new Anthropic organization API key and returns a populated `Secret`.
- `verify`: makes a real Anthropic Admin API request with the new secret.
- `revoke`: deletes an Anthropic organization API key. `404` is treated as success.
- `list`: lists organization API keys for incident discovery.

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
