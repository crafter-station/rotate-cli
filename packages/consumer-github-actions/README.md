# @rotate/consumer-github-actions

GitHub Actions secrets consumer for rotate-cli.

## Supported Operations

- `propagate`: writes a secret to a repository Actions secret using GitHub's encrypted secrets API.
- `verify`: confirms the repository secret exists and its `updated_at` timestamp is at or after the rotated secret creation time.
- `trigger`: not implemented. GitHub Actions reads repository secrets on the next workflow run.

`propagate` is idempotent. It deletes the repository secret first, treats `404` as success, then recreates it with the new encrypted value.

## Auth Setup

Preferred auth uses the official GitHub CLI:

```sh
gh auth login
```

The consumer reads the token with:

```sh
gh auth token
```

Fallback auth is available for development and CI:

```sh
export GITHUB_TOKEN=ghp_...
```

The token must have permission to manage repository Actions secrets. For fine-grained tokens, grant repository access and Actions secrets write access for the target repository.

## Config Example

```yaml
version: 1

secrets:
  - id: openai-main
    adapter: openai
    metadata:
      account: primary
    consumers:
      - type: github-actions
        params:
          repo: crafter-station/elements
          secret_name: OPENAI_API_KEY
```
