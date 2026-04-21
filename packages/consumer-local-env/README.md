# @rotate/consumer-local-env

Local `.env` file consumer for rotate-cli.

## Supported Operations

- `propagate`: writes the rotated secret value to a local `.env` file.
- `verify`: re-reads the local `.env` file and confirms the configured variable matches the new secret value.
- `trigger`: not supported. Local `.env` files do not have a provider-side reload or redeploy step.

`propagate` is idempotent. It replaces an existing variable line when present and appends the variable when absent. Other variables, blank lines, and comments are preserved. Writes are atomic by writing a sibling temporary file and renaming it over the target path.

## Auth Setup

No provider authentication is required. This consumer uses local filesystem access from the current process.

The configured `path` must be absolute or start with `~`. The parent directory is created if it does not exist.

## Config Example

```yaml
version: 1

secrets:
  - id: openai-main
    adapter: openai
    metadata:
      project: primary
    consumers:
      - type: local-env
        params:
          path: ~/.config/my-app/.env
          var_name: OPENAI_API_KEY
```
