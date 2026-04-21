# rotate-cli

> Agent-first secrets rotation CLI. Local-first. Zero servers.

rotate-cli is the first secrets rotation tool designed for the AI-native stack. Your master credentials never leave your machine — borrowed from CLIs you already trust (`vercel`, `gh`, `clerk`). It ships an **agent mode** with hard guardrails so Claude Code and Codex can rotate safely, and an **incident mode** that responds to vendor breaches in a single command.

Built by [Crafter Station](https://crafterstation.com) after the April 2026 Vercel breach left one of us staring at 1,516 env vars flagged *Need to Rotate*.

**Status**: `v0.1.0-dev` — pre-release, untested against live production rotations. Not yet on npm.

---

## Install

```bash
# TODO: publishing to npm once v0.1 is smoke-tested against real providers.
# For now, clone and run:
git clone https://github.com/crafter-station/rotate-cli
cd rotate-cli
bun install
bun packages/cli/src/bin.ts --help
```

---

## Quick start

```bash
# 1. Describe what you rotate
cat > rotate.config.yaml <<'YAML'
version: 1
secrets:
  - id: clerk-prod
    adapter: clerk
    metadata:
      instance_id: ins_abc123
    tags: [production]
    consumers:
      - type: vercel-env
        params:
          project: prj_xxx
          team: team_yyy
          var_name: CLERK_SECRET_KEY
YAML

# 2. See the plan
rotate plan --tag production

# 3. Respond to an incident (dry-run first)
rotate incident .rotate/incidents/vercel-apr-2026.yaml --dry-run

# 4. Execute (grace period keeps the old secret valid for 1h)
rotate incident .rotate/incidents/vercel-apr-2026.yaml --yes --reason "vendor breach response"

# 5. Close the rotation once consumers have redeployed
rotate revoke <rotation-id>
```

---

## What's covered

17 adapters and 3 consumers in v0.1, rotating `560+` real-world secret variables across the modern stack.

### Adapters (creators of new secrets)

| Adapter | Covers | API |
|---|---|---|
| `clerk` | `CLERK_SECRET_KEY`, `CLERK_WEBHOOK_SECRET` | [PLAPI](https://clerk.com/docs) |
| `openai` | `OPENAI_API_KEY` (admin keys) | [Admin API](https://platform.openai.com/docs/api-reference/admin-api-keys) |
| `anthropic` | `ANTHROPIC_API_KEY` (admin) | [Admin API](https://docs.anthropic.com/en/api/admin-api/apikeys/listapikeys) |
| `resend` | `RESEND_API_KEY` | [Resend API](https://resend.com/docs/api-reference/api-keys) |
| `supabase` | `SUPABASE_SERVICE_ROLE_KEY`, anon, jwt | [Management API](https://supabase.com/docs/reference/api) |
| `neon` | `NEON_API_KEY` (project API keys) | [Neon API](https://api-docs.neon.tech/) |
| `neon-connection` | `DATABASE_URL`, `POSTGRES_*` (reset-password) | [Neon API](https://api-docs.neon.tech/reference/resetprojectbranchrolepassword) |
| `github-token` | `GITHUB_TOKEN` (installation tokens) | [GitHub REST](https://docs.github.com/en/rest) |
| `vercel-token` | `VERCEL_TOKEN` | [Vercel API](https://vercel.com/docs/rest-api) |
| `ai-gateway` | `AI_GATEWAY_API_KEY` | Vercel token wrapper |
| `upstash` | `UPSTASH_REDIS_REST_TOKEN`, Vector | [Developer API](https://upstash.com/docs/devops/developer-api/introduction) |
| `vercel-kv` | Legacy `KV_*` vars (alias of upstash, [doc](https://vercel.com/docs/redis)) | — |
| `polar` | `POLAR_ACCESS_TOKEN`, `POLAR_WEBHOOK_SECRET` | [Polar API](https://docs.polar.sh) |
| `fal` | `FAL_API_KEY` | [fal.ai](https://docs.fal.ai) |
| `elevenlabs` | service-account API keys | [ElevenLabs](https://elevenlabs.io/docs) |
| `turso` | `TURSO_AUTH_TOKEN`, `TURSO_DATABASE_URL` | [Turso Platform API](https://docs.turso.tech) |
| `local-random` | `SESSION_SECRET`, `JWT_SECRET`, custom HMAC | `crypto.randomBytes` |

### Consumers (destinations for new values)

| Consumer | Writes to |
|---|---|
| `vercel-env` | Vercel project env vars + redeploy trigger |
| `github-actions` | GitHub repo/org secrets (sealed-box encrypted) |
| `local-env` | `.env` files on disk (atomic write) |

Run `rotate doctor` to see what is authenticated on your machine.

---

## Agent mode

Set `ROTATE_CLI_AGENT_MODE=1` when invoking from an LLM. This enables hard guardrails so agents can rotate without running away with the store.

```bash
ROTATE_CLI_AGENT_MODE=1 rotate apply openai-prod \
  --reason "vercel breach response 2026-04-19" \
  --max-rotations 1 \
  --audit-log ~/.kai/audit/rotate-$(date +%F).jsonl \
  --yes
```

Guardrails enforced:

- `--reason` required (min 5 chars) — shows up in audit log.
- `--yes` required — no TTY prompts to hang the agent.
- `--audit-log` required — every action appended to JSONL.
- `--max-rotations N` — hard cap; exceeding aborts with exit 5.
- `--no-verify` forbidden.
- `--force-revoke` required to invalidate the old secret.
- Global rate limit: 1 rotation per minute per machine.
- Per-rotation cap: 50 consumers.

See [`docs/AGENT_MODE.md`](docs/AGENT_MODE.md) for the full spec.

---

## How it works

Every rotation goes through the same pipeline:

```
 create ── propagate ── trigger ── verify ── (grace) ── revoke
   │          │           │          │           │          │
   │          │           │          │           │          └─ old secret invalidated
   │          │           │          │           └─ waits until consumers sync
   │          │           │          └─ hits provider + consumers to confirm
   │          │           └─ redeploys / reloads consumers
   │          └─ writes new value to every consumer (parallel, fail-fast)
   └─ fetches a fresh credential from the provider
```

State lives on disk at `~/.config/rotate-cli/` (checkpoints, history, audit logs). If a step fails mid-rotation, `rotate resume <id>` picks up where it left off.

Grace period is **verify-based** by default with a 1h floor — the orchestrator only lets you revoke once every consumer confirms it sees the new secret.

---

## Why local-first

rotate-cli has no servers. It has no SaaS dashboard. It does not phone home. It borrows auth tokens from CLIs you already have installed (`vercel`, `gh`, `clerk`) or from env vars you provide.

This design is deliberate. A centralised rotation service is itself a breach target — the exact pattern that caused the Vercel incident. rotate-cli holds no keys between runs, only the plan.

When you are done rotating, there is nothing for an attacker to steal except your own machine. If your machine is already compromised, you have bigger problems than secrets rotation.

---

## Contributing

Adapters are how rotate-cli grows. Each adapter is a single file implementing the `Adapter` interface in [`docs/ADAPTER_SPEC.md`](docs/ADAPTER_SPEC.md), plus a fetch-mocked test file. Pre-flight research for each provider lives under [`docs/adapter-research/`](docs/adapter-research/).

To add a new adapter:

1. Read [`docs/ADAPTER_SPEC.md`](docs/ADAPTER_SPEC.md).
2. Copy the shape of [`packages/adapter-clerk/`](packages/adapter-clerk/) — it's the reference impl.
3. Register your adapter in [`packages/cli/src/register.ts`](packages/cli/src/register.ts).
4. Open a PR with the research report, the adapter, and at least one mocked-fetch test.

Providers that lack a rotation API will land in **v0.2** via human-in-the-loop adapters (GitHub OAuth App, Firecrawl, Uploadthing, Groq, Twitch, Vercel Blob, Stripe secret keys, Sentry).

---

## Docs

- [`docs/ADAPTER_SPEC.md`](docs/ADAPTER_SPEC.md) — Adapter + Consumer interface
- [`docs/CLI_SPEC.md`](docs/CLI_SPEC.md) — Commands, flags, exit codes, output envelope
- [`docs/AGENT_MODE.md`](docs/AGENT_MODE.md) — Guardrails for LLM callers
- [`docs/adapter-research/`](docs/adapter-research/) — Per-provider research notes (source of truth for each adapter's behaviour)

---

## License

MIT © [Crafter Station](https://crafterstation.com)
