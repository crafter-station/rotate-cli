# rotate-cli

Agent-first secrets rotation CLI. Local-first (zero servers). Built as response to Vercel April 2026 breach.

## Pitch

First secrets rotation tool designed for the AI-native stack. Master credentials never leave your machine — borrowed from CLIs you already trust (`vercel`, `gh`, `clerk`). Ships an agent mode with hard guardrails (audit logs, reason-required, rate limits) so Claude Code and Codex can rotate safely. Introduces **incident mode**: point it at a vendor's post-mortem URL, rotate everything affected across your stack in one pass.

## Status

**Fase 1 — skeleton in progress** (2026-04-21). See `docs/` for specs, `04_Projects/_shaping/rotate-cli/` in vault for shape.

## Packages

| Package | Purpose | Status |
|---|---|---|
| `@rotate/core` | Orchestrator, CLI, types, envelope, agent-mode | building |
| `@rotate/adapter-clerk` | Clerk secret keys (reference adapter) | building |
| `@rotate/consumer-vercel-env` | Vercel env var consumer (reference) | building |

Tier 1 (overnight Fase 2): adapter-vercel-token, adapter-openai, adapter-anthropic, adapter-github-token, adapter-resend, adapter-supabase, adapter-neon, consumer-github-actions, consumer-local-env, helpers-rest.

## Docs

- [ADAPTER_SPEC.md](docs/ADAPTER_SPEC.md) — Adapter + Consumer contract
- [CLI_SPEC.md](docs/CLI_SPEC.md) — Commands, flags, exit codes
- [AGENT_MODE.md](docs/AGENT_MODE.md) — Guardrails for LLM callers

## License

MIT (planned, pre-release)
