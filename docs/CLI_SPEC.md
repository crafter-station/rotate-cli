# CLI_SPEC.md

Command surface for `rotate`. Locked 2026-04-21. Changes require a spec PR.

## Global flags

| Flag | Effect |
|---|---|
| `--json` | Force JSON output (default if stdout is not a TTY) |
| `--pretty` | Force human output (default if stdout IS a TTY) |
| `--yes` / `-y` | Skip confirmation prompts |
| `--config <path>` | Override config path (default: `./rotate.config.yaml`) |
| `--reason <str>` | Required in agent mode. Free-text justification. |
| `--dry-run` | Alias of `rotate plan` for any mutating command |

## Environment variables

| Var | Effect |
|---|---|
| `ROTATE_CLI_AGENT_MODE=1` | Enables agent-mode guardrails (see AGENT_MODE.md) |
| `ROTATE_CLI_YES=1` | Same as `--yes` globally |
| `ROTATE_CLI_CONFIG` | Default `--config` path |
| `ROTATE_CLI_STATE_DIR` | Override `~/.config/rotate-cli/` |
| `NO_COLOR=1` | Disable color in human output |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | User error (bad flags, config invalid, selector matches nothing) |
| 2 | Provider error (auth failed, rate limited, 5xx) |
| 3 | Verify failed (new secret doesn't work) |
| 4 | In-grace warning (command succeeded but something's pending) |
| 5 | Agent-mode guardrail violation (rate limit, max-rotations hit, etc) |
| 130 | Interrupted (SIGINT) |

## Commands

### `rotate init`
Create `~/.config/rotate-cli/` + writes a starter `rotate.config.yaml` template. Interactive unless `--yes`.

### `rotate doctor`
Verifies auth state for every adapter referenced in the current config. Prints a table of `adapter | status | auth method`. Exit 2 if any required adapter can't auth.

### `rotate config add <adapter>`
Interactive prompts to add a new secret entry to `rotate.config.yaml`. With `--yes`, reads flags: `--id`, `--metadata k=v,...`, `--consumer type:param1=x,param2=y`.

### `rotate config list`
Print all secrets tracked. Columns: `id | adapter | consumers`.

### `rotate config validate`
Parse the config, resolve against available adapters, check permissions. Does NOT call providers.

### `rotate plan <selector>`
Dry-run. Prints the exact rotation plan: what will be created, propagated where, what will be revoked (nothing — revoke is separate). Safe to run anytime.

### `rotate apply <selector>`
Executes a rotation: create new secret → propagate to all consumers → verify → DO NOT revoke.

Flags:
- `--revoke-after <duration>` — schedule auto-revoke (default: never, revoke is manual).
- `--no-verify` — skip verify step. Dangerous.
- `--parallel <n>` — consumer propagation concurrency (default 10).

Prints `rotation_id` on success. Use that for `status` / `revoke` / `rollback`.

### `rotate status [<rotation-id>]`
Without ID: list all rotations in grace. With ID: show detail (consumers, verify status, eligible-for-revoke?).

Exit 4 if any listed rotation has consumers still pending sync.

### `rotate revoke <rotation-id>`
Revoke the OLD secret for a rotation in grace. Fails with exit 4 if any consumer hasn't synced yet.

Flags:
- `--force` — revoke even if consumers not synced. `--reason` required.

### `rotate rollback <rotation-id>`
Undo a rotation still in grace: delete the new secret from the provider, restore the old value to all consumers. Only valid before revoke.

### `rotate incident <incident.yaml>`
Apply an incident file. Equivalent to:
1. Resolve selectors in `incident.yaml` against current config.
2. `rotate plan` each affected rotation. Print summary.
3. Confirm (unless `--yes`).
4. `rotate apply` each in sequence.
5. Print combined `rotation_id`s.

Flags:
- `--revoke-after <duration>` — propagated to each apply.
- `--from-url <url>` — fetch incident YAML from URL (the agent pattern).

### `rotate history [<rotation-id>]`
Without ID: list last 50 rotations across all states. With ID: detailed log of steps, timestamps, errors.

## Output envelope (JSON mode)

Every command emits a single JSON object:

```json
{
  "version": "1",
  "command": "apply",
  "status": "success",
  "data": { /* command-specific */ },
  "errors": [],
  "next_actions": [ /* agent hints */ ],
  "meta": {
    "timestamp": "2026-04-21T18:00:00Z",
    "duration_ms": 3241,
    "agent_mode": false
  }
}
```

- `status`: `success | partial | error | in_progress`
- `errors[]`: array of `{code, message, provider?, retryable}`
- `next_actions[]`: array of human-readable next command hints (critical for agents)

JSON Schema exposed via `rotate schema <command>`.

## Selector syntax

### Identifier (happy path)
```
rotate apply clerk/main-app
rotate apply openai/primary
```

### Query (wildcards for incidents)
```
rotate apply --provider clerk
rotate apply --tag production
rotate apply --provider vercel --tag non-sensitive
```

### Compound
```
rotate apply openai/primary clerk/main-app
```

## State layout

```
~/.config/rotate-cli/
├── config.yaml                 # global defaults (user-level)
├── state/
│   └── rot_<id>.json           # checkpoints for in-flight rotations
├── history/
│   └── YYYY-MM.jsonl           # append-only history (month-sharded)
├── audit/
│   └── agent-YYYY-MM-DD.jsonl  # agent-mode audit log
└── secrets.age                 # encrypted fallback store
```

Project-local:
```
<repo>/
├── rotate.config.yaml          # declarative secret list, git-committed
└── .rotate/
    └── incidents/              # project-scoped incident YAMLs
        └── YYYY-MM-DD-slug.yaml
```

## Example config

```yaml
version: 1

defaults:
  grace_period_floor: 1h

secrets:
  - id: clerk-hack0
    adapter: clerk
    metadata:
      instance_id: ins_abc123
    consumers:
      - type: vercel-env
        params:
          project: hack0
          var_name: CLERK_SECRET_KEY

  - id: openai-main
    adapter: openai
    tags: [production, ai-stack]
    consumers:
      - type: vercel-env
        params:
          project: peru-ai-hackathon
          var_name: OPENAI_API_KEY
      - type: vercel-env
        params:
          project: hack0
          var_name: OPENAI_API_KEY
      - type: github-actions
        params:
          repo: crafter-station/elements
          secret_name: OPENAI_API_KEY
```

## Example incident

```yaml
# .rotate/incidents/vercel-apr-2026.yaml
version: 1
id: vercel-apr-2026
published: 2026-04-19
reference: https://vercel.com/kb/bulletin/vercel-april-2026-security-incident
severity: high
scope:
  - provider: clerk
    filter:
      tag: non-sensitive
  - provider: openai
    filter:
      exposed_via: vercel-env
      tag: non-sensitive
```

Invocation:
```
rotate incident .rotate/incidents/vercel-apr-2026.yaml --yes --reason "Vercel Context.ai breach response"
```
