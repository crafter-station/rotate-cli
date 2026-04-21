# AGENT_MODE.md

Guardrails for LLM callers. Locked 2026-04-21.

## Activation

Set `ROTATE_CLI_AGENT_MODE=1`. This changes three things:
1. **Mandatory flags** are enforced (see below).
2. **Rate limits** are active.
3. **Audit log** is always written.

Agent mode is explicit. Humans running `rotate` never trip these guards unless they opt in.

## Mandatory flags in agent mode

| Flag | Required when | Reason |
|---|---|---|
| `--reason <string>` | any mutating command (`apply`, `revoke`, `rollback`, `incident`) | Traceability — audit log captures the rationale |
| `--yes` | same | No TTY prompt to hang an agent |
| `--max-rotations <n>` | `apply` with query selector; `incident` | Hard cap. If the selector resolves to more, abort. |
| `--audit-log <path>` | any mutating command | Agent cannot skip audit trail |

If any required flag is missing, exit 5 with message `agent_mode: missing required flag --<X>`.

## Rate limits

- **Global**: max 1 rotation per 60 seconds across all commands. Applied per-machine (state in `~/.config/rotate-cli/state/rate-limit.json`).
- **Per-rotation**: max 50 consumers in a single `apply`. If a rotation's `consumers` list exceeds this, abort.
- **Per-incident**: max 20 distinct secrets rotated in a single `incident` invocation (use `--max-rotations` to lower).

On rate-limit violation: exit 5 with `{ "errors": [{"code": "agent_rate_limit", "message": "..."}] }`.

## Revoke gating

In agent mode, `rotate revoke` requires `--force-revoke` explicitly. The default behavior allows rotations to stay in grace indefinitely, which is the safe default for agents.

Rationale: the most dangerous operation is revoking before consumers have synced. Agents should rotate eagerly but revoke conservatively. `--force-revoke` makes the risk explicit.

## Audit log format

Append-only JSONL at the path given by `--audit-log`. One entry per command invocation:

```json
{
  "timestamp": "2026-04-21T18:00:00Z",
  "command": "apply",
  "args": ["openai/primary"],
  "reason": "vercel-apr-2026 breach response",
  "agent_mode": true,
  "rotation_id": "rot_abc123",
  "status": "success",
  "secrets_affected": ["openai/primary"],
  "consumers_affected": [
    {"type": "vercel-env", "project": "hack0", "status": "synced"}
  ],
  "duration_ms": 3241,
  "exit_code": 0
}
```

Errors also produce an entry with `status: "error"` and the error array.

Recommended path: `~/.kai/audit/rotate-<YYYY-MM-DD>.jsonl` (rotate-daily, Kai can ingest).

## Safe defaults under agent mode

- `apply` NEVER revokes implicitly. `--revoke-after` flag is ignored under agent mode (warn + continue).
- `rollback` requires `--confirm-rollback` flag. Belt-and-braces.
- `incident` prints full plan to stderr before executing, even with `--yes`.
- Verify step cannot be skipped. `--no-verify` exits 5.

## Example safe agent invocation

```bash
ROTATE_CLI_AGENT_MODE=1 rotate apply openai/primary \
  --reason "Vercel Apr 2026 breach — Context.ai OAuth compromise" \
  --max-rotations 1 \
  --audit-log ~/.kai/audit/rotate-$(date +%Y-%m-%d).jsonl \
  --json \
  --yes
```

Expected stderr envelope includes `next_actions`:
```json
{
  "next_actions": [
    "Run `rotate status rot_abc123 --json` to check consumer sync",
    "After all consumers sync, run `ROTATE_CLI_AGENT_MODE=1 rotate revoke rot_abc123 --force-revoke --reason '...' --json`"
  ]
}
```

## Anti-patterns (will exit 5)

- Calling `apply --no-verify` — exit 5.
- Calling `apply` without `--reason` — exit 5.
- Calling `revoke` on a rotation where any consumer is not synced, without `--force-revoke` — exit 5.
- Calling `incident` with `--revoke-after` set — exit 5 (revoke is explicit in agent mode).
- Rotating more than 50 consumers in one `apply` — exit 5.
- More than 1 rotation per minute — exit 5.
- Missing `--audit-log` — exit 5.

## Philosophy

Agents should be able to respond to breaches, but they cannot run away with the store. Every guardrail here exists because of a plausible failure mode: agent loops, agent hallucinates a selector, agent revokes before consumers are ready.

If a guardrail gets in your way, the answer is NOT to weaken it. The answer is to break the work into smaller pieces so the guardrails don't fire.
