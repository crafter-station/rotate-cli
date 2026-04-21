# AGENTS.md

## Repo Shape
- Root is a Bun workspace monorepo: `workspaces: ["packages/*"]` in `package.json`.
- `landing/` is a separate Bun project with its own `package.json` and `bun.lock`; root workspace commands do not include it.

## Commands
- Root verification commands:
  - `bun test`
  - `bun run typecheck`
  - `bun run build`
- `bun run check` is not read-only: it runs `bunx @biomejs/biome check --write .` and will modify files.
- Package tests live under `packages/*/test`; root `bun test` runs them.

## CLI Entry Points
- CLI bin entrypoint: `packages/cli/src/bin.ts`.
- CLI boot calls `registerAll()` from `packages/cli/src/register.ts` before `runCli()`.
- Adapter and consumer registration is manual in `packages/cli/src/register.ts`; adding a package is not enough to make it reachable from the CLI.

## Implemented CLI Surface
- Treat `packages/core/src/cli.ts` as the source of truth for supported commands and flags.
- Commands implemented today: `init`, `doctor`, `plan`, `apply`, `status`, `revoke`, `incident`.

## Runtime Behavior
- Rotation state lives under `ROTATE_CLI_STATE_DIR` or `~/.config/rotate-cli`.
- Relevant subdirectories are `state/`, `history/`, and `audit/`.
- `rotate doctor` authenticates all registered adapters and consumers, not just entries referenced by the current config.

## Architecture
- Core orchestration lives in `packages/core`.
- Provider-specific secret creation/revoke logic lives in adapter packages.
- Secret propagation, trigger, and consumer-side verification logic lives in consumer packages.

## Docs Drift
- `docs/CLI_SPEC.md` and `docs/AGENT_MODE.md` currently drift from the implementation in places; prefer code when they conflict.
- Explicit mismatch: code implements `rotate revoke --force-revoke`, while docs mention `--force`.
