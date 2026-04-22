# rotate-cli

> Agent-first secrets rotation CLI. Local-first. Zero servers.

`rotate-cli` is the first secrets rotation tool designed for the AI-native stack. Your master credentials never leave your machine. They are borrowed from CLIs you already trust (`vercel`, `gh`, `clerk`). It ships an **agent mode** with hard guardrails so Claude Code and Codex can rotate safely, and an **incident mode** that responds to vendor breaches in a single command.

Built by [Crafter Station](https://crafterstation.com) after the April 2026 Vercel breach left one of us staring at 1,516 env vars flagged *Need to Rotate*.

**Status**: `v0.1.0-dev`. Pre-release, not yet on npm. Ownership detection and dedup are battle-tested against a 318-project Vercel team. `apply` end-to-end smoke tests against real providers are in progress.

Docs: [rotate-cli.crafter.run/docs](https://rotate-cli.crafter.run/docs)

---

## Install

```bash
# npm publish pending
git clone https://github.com/crafter-station/rotate-cli
cd rotate-cli
bun install
bun link                # exposes `rotate-cli` globally
rotate-cli --help
```

---

## Three commands, one flow

```bash
# 1. Discover every env var across every Vercel project
rotate-cli scan

# 2. For each mapped secret, decide mine vs someone else's
rotate-cli who --from-scan --tag non-sensitive

# 3. Rotate the ones you own. Auto-only is the default phase.
rotate-cli apply --from-scan --tag non-sensitive \
  --yes --confirm-bulk \
  --reason "vercel-apr-2026 breach"

# 4. Close rotations once consumers have redeployed
rotate-cli status                     # see in-flight rotations
rotate-cli revoke <rotation-id>       # invalidate the old secret
```

If you prefer explicit config, write a `rotate.config.yaml` with declared `secrets` and `consumers`. See `docs/ADAPTER_SPEC.md` for the schema.

---

## What's covered

**22 adapters** and **3 consumers** today, covering the majority of env vars on a modern Vercel deployment.

### Adapters (creators of new secrets)

Adapters run in one of two modes:

- **`auto`**: call provider APIs to create and revoke. Unattended, safe in CI and agent mode.
- **`manual-assist`**: pause per rotation, print instructions, and prompt the user to paste a new value from the provider dashboard. Propagation to consumers still runs automatically. Requires an interactive TTY.

| Adapter | Mode | Covers | API / strategy |
|---|---|---|---|
| `clerk` | auto | `CLERK_SECRET_KEY`, `CLERK_WEBHOOK_SIGNING_SECRET` | PLAPI `/v1/platform/applications` + JWKS |
| `openai` | auto | `OPENAI_API_KEY`, `OPENAI_ADMIN_KEY` | Admin API |
| `anthropic` | auto | `ANTHROPIC_API_KEY`, `ANTHROPIC_ADMIN_KEY` | Admin API |
| `resend` | auto | `RESEND_API_KEY` | Resend API domain list |
| `supabase` | auto | service role, anon, jwt | Management API |
| `neon` | auto | `NEON_API_KEY` | Neon API `/users/me` |
| `neon-connection` | auto | `DATABASE_URL`, `POSTGRES_*` | Neon reset-password + endpoint index |
| `github-token` | auto | `GITHUB_TOKEN` (installation) | GitHub REST |
| `vercel-token` | auto | `VERCEL_TOKEN` | Vercel `/v5/user/tokens/current` |
| `vercel-ai-gateway` | auto | `AI_GATEWAY_API_KEY` | Vercel token wrapper |
| `upstash` | auto | Redis + Vector REST tokens | Upstash Developer API |
| `polar` | auto | `POLAR_ACCESS_TOKEN`, `POLAR_WEBHOOK_SECRET` | Polar API |
| `fal` | auto | `FAL_API_KEY`, `FAL_KEY` | fal Platform API |
| `elevenlabs` | auto | `ELEVENLABS_API_KEY` | ElevenLabs service-account keys |
| `turso` | auto | `TURSO_AUTH_TOKEN`, `TURSO_DATABASE_URL` | Turso Platform API |
| `exa` | auto | `EXA_API_KEY` | Exa Team Management API |
| `uploadthing` | manual-assist | `UPLOADTHING_TOKEN` | Dashboard + token format-decode |
| `vercel-blob` | manual-assist | `BLOB_READ_WRITE_TOKEN` | Dashboard; ownership-only for now |
| `trigger-dev` | manual-assist | `TRIGGER_SECRET_KEY`, `TRIGGER_ACCESS_TOKEN` | Dashboard |
| `firecrawl` | manual-assist | `FIRECRAWL_API_KEY` | Dashboard |
| `vercel-kv` | no-check | Legacy `KV_*` vars | Delegates to upstash |
| `local-random` | no-check | `SESSION_SECRET`, `JWT_SECRET`, custom HMAC | `crypto.randomBytes` |

### Consumers (destinations for new values)

| Consumer | Writes to |
|---|---|
| `vercel-env` | Vercel project env vars + redeploy trigger |
| `github-actions` | GitHub repo/org secrets (sealed-box encrypted) |
| `local-env` | `.env` files on disk (atomic write) |

Run `rotate-cli doctor` to see what is authenticated on your machine.

---

## Ownership detection

Before rotating anything, `rotate-cli who` decides whether each secret belongs to the authenticated admin or to a teammate. Rotating a teammate's secret would either fail (wrong credentials) or succeed against a provider account you don't own (charging them, invalidating their consumers). `who` catches both cases with a read-only introspection pass.

Four verdicts:

| Verdict | Glyph | Meaning |
|---|---|---|
| `self` | `✓` | Strong evidence the admin owns it. Safe to rotate. |
| `other` | `✗` | Strong evidence it belongs to someone else. Skip unless `--force-rotate-other`. |
| `unknown` | `?` | Adapter couldn't decide. Provider API limitation. |
| `no-check` | `○` | Adapter has no ownership detection (local-random, alias adapters). |

Each adapter picks a strategy: `format-decode`, `api-introspection`, `list-match`, or `sibling-inheritance`. See [docs/who](https://rotate-cli.crafter.run/docs/who) for details.

Measured on Hunter's vault (451 non-sensitive secrets across 318 Vercel projects):

```
Before ownership work:  29 self ·  64 other · 336 unknown · 22 no-check
After ownership work:   77 self · 280 other ·  69 unknown · 22 no-check
```

**76% reduction in unknown verdicts.**

---

## Agent mode

Set `ROTATE_CLI_AGENT_MODE=1` when invoking from an LLM. This enables hard guardrails so agents can rotate without running away with the store.

```bash
ROTATE_CLI_AGENT_MODE=1 rotate-cli apply --from-scan --auto-only \
  --yes \
  --reason "vercel breach response 2026-04-19" \
  --max-rotations 50 \
  --audit-log ./rotations.log
```

Guardrails enforced:

- Always emits the JSON envelope, never pretty output.
- `--reason` required. Shows up in audit log.
- `--yes` required. No TTY prompts to hang the agent.
- `--max-rotations N` required for `apply` and `incident`. Hard cap.
- `--no-ownership-check`, `--force-rotate-other`, `--no-verify`, `--manual-only`: forbidden.
- Manual-assist adapters return `code: "unsupported"` immediately. The agent surfaces deferred rotations to a human.

See [docs/agent-mode](https://rotate-cli.crafter.run/docs/agent-mode) for the full contract.

---

## How it works

Every rotation goes through the same pipeline:

```
 create  →  propagate  →  trigger  →  verify  →  (grace)  →  revoke
   │           │            │           │            │           │
   │           │            │           │            │           └─ old secret invalidated
   │           │            │           │            └─ waits until consumers sync
   │           │            │           └─ hits provider + consumers to confirm
   │           │            └─ redeploys / reloads consumers
   │           └─ writes new value to every consumer (parallel, fail-fast)
   └─ fetches a fresh credential from the provider
```

State lives on disk at `~/.config/rotate-cli/` (checkpoints, history, audit logs). If a step fails mid-rotation, the old secret stays valid and the rotation is resumable.

Grace period is **verify-based** by default with a 1h floor. The orchestrator only lets you revoke once every consumer confirms it sees the new secret.

### Dedup

A single secret value can show up in many Vercel entries (dev + preview + prod for the same project, or the same key copy-pasted across sibling projects). `rotate-cli apply` groups entries by `(adapter, sha256(currentValue))` and rotates each group **once**. The representative's consumer list is the union of every duplicate, so propagation still reaches every Vercel env that held the old value.

In Hunter's vault, 76 self entries reduce to 58 unique rotations. You see this in the `who` summary: `76 self (58 unique)`.

---

## Why local-first

rotate-cli has no servers. It has no SaaS dashboard. It does not phone home. It borrows auth tokens from CLIs you already have installed (`vercel`, `gh`, `clerk`) or from env vars you provide.

This design is deliberate. A centralised rotation service is itself a breach target. That is the exact pattern that caused the Vercel incident. rotate-cli holds no keys between runs, only the plan.

When you are done rotating, there is nothing for an attacker to steal except your own machine. If your machine is already compromised, you have bigger problems than secrets rotation.

---

## Contributing

Adapters are how rotate-cli grows. Each adapter is a single file implementing the `Adapter` interface in [`docs/ADAPTER_SPEC.md`](docs/ADAPTER_SPEC.md), plus a fetch-mocked test file. Pre-flight research for each provider lives under [`docs/adapter-research/`](docs/adapter-research/).

To add a new adapter:

1. Read [`docs/ADAPTER_SPEC.md`](docs/ADAPTER_SPEC.md).
2. Copy the shape of [`packages/adapter-clerk/`](packages/adapter-clerk/). It's the reference impl.
3. Declare `readonly mode: "auto" | "manual-assist"` on the exported Adapter. Auto is the default; manual-assist adapters must use `spec.io` from the `RotationSpec` for prompts.
4. Register your adapter in [`packages/cli/src/register.ts`](packages/cli/src/register.ts).
5. Add its env var name(s) to `VAR_TO_ADAPTER` in [`packages/core/src/scan.ts`](packages/core/src/scan.ts).
6. Open a PR with the research report, the adapter, and at least one mocked-fetch test.

Tier-3 providers without a rotation API are documented under [`docs/adapter-research/unmapped/`](docs/adapter-research/unmapped/).

---

## Docs

- [`docs/ADAPTER_SPEC.md`](docs/ADAPTER_SPEC.md). Adapter + Consumer interface.
- [`docs/CLI_SPEC.md`](docs/CLI_SPEC.md). Commands, flags, exit codes, output envelope.
- [`docs/AGENT_MODE.md`](docs/AGENT_MODE.md). Guardrails for LLM callers.
- [`docs/adapter-research/`](docs/adapter-research/). Per-provider research notes.
- [`rotate-cli.crafter.run/docs`](https://rotate-cli.crafter.run/docs). Hosted docs site.

---

## License

MIT © [Crafter Station](https://crafterstation.com)
