# ADAPTER_SPEC.md

Contract for adapters and consumers in rotate-cli. This is the source of truth — Fase 2 agents MUST follow these interfaces exactly. Deviations require a spec PR first.

## Core concepts

- **Secret**: an identifier + value pair that terminates as an env var in a runtime. API keys, tokens, DB connection strings.
- **Adapter**: emits secrets. Implements `create`, `verify`, `revoke`, optional `list`. One adapter per provider (e.g. Clerk, OpenAI, Vercel Tokens).
- **Consumer**: receives secrets and writes them to a target. Implements `propagate`, optional `trigger` (redeploy) and `verify` (confirm sync). One consumer per target type (Vercel env, GH Actions, local .env).
- **A service can be both**: Vercel is an adapter (emits access tokens) AND a consumer (receives env vars for projects). They live in separate packages.

## Types (TypeScript)

```ts
// Secret — a tracked credential
export interface Secret {
  id: string;                    // e.g. "clerk/main-app" or "openai/primary"
  provider: string;              // adapter name
  value: string;                 // the actual credential value (in memory only)
  metadata: Record<string, string>; // provider-specific (e.g. clerk instance_id)
  createdAt: string;             // ISO 8601
  expiresAt?: string;            // ISO 8601, if provider schedules expiry
}

// AuthContext — how an adapter authenticates to its provider
export type AuthContext =
  | { kind: "cli-piggyback"; tool: string; tokenPath?: string; token: string }
  | { kind: "encrypted-file"; path: string; token: string }
  | { kind: "env"; varName: string; token: string };

// RotationSpec — declarative input for create()
export interface RotationSpec {
  secretId: string;              // logical ID from rotate.config.yaml
  adapter: string;               // adapter name
  metadata: Record<string, string>; // adapter-specific params (e.g. clerk instance_id, vercel team)
  reason?: string;               // propagated from --reason in agent mode
}

// RotationResult — outcome of an adapter operation
export interface RotationResult<T = Secret> {
  ok: boolean;
  data?: T;
  error?: AdapterError;
}

// AdapterError — standardized error shape
export interface AdapterError {
  code: AdapterErrorCode;
  message: string;
  provider: string;
  retryable: boolean;
  cause?: unknown;
}

export type AdapterErrorCode =
  | "auth_failed"          // auth context invalid / expired
  | "rate_limited"         // provider returned 429
  | "not_found"            // secret doesn't exist (revoke/verify on missing)
  | "provider_error"       // 5xx from provider
  | "network_error"        // connectivity
  | "invalid_spec"         // bad input
  | "unsupported";         // operation not supported by provider
```

## Adapter interface

```ts
export interface Adapter {
  /** Stable short name, kebab-case. e.g. "clerk", "vercel-token", "openai". */
  readonly name: string;

  /** Resolve auth context. Throws AdapterError{code: "auth_failed"} if unavailable. */
  auth(): Promise<AuthContext>;

  /** Create a new secret. Does NOT revoke old one. */
  create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>>;

  /** Verify a secret works by calling a provider-side lightweight endpoint.
   *  MUST make a real network call — syntactic-only verify is not allowed. */
  verify(secret: Secret, ctx: AuthContext): Promise<RotationResult<boolean>>;

  /** Revoke a secret. Idempotent — calling twice must not error. */
  revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>>;

  /** List existing secrets matching a filter. Optional — used for incident mode. */
  list?(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>>;
}
```

**Rules:**
- `auth()` MUST NOT prompt the user. If auth is missing, return an error.
- `create()` MUST return a fully-populated `Secret` including `value`.
- `verify()` MUST make a real network call. The minimum is the provider's equivalent of `GET /me` or `whoami`.
- `revoke()` MUST be idempotent. If the secret is already gone, return `{ok: true}`.
- Adapters MUST NOT persist secrets to disk — that's the orchestrator's job.
- Adapters MUST NOT depend on other adapters.

## Consumer interface

```ts
export interface Consumer {
  readonly name: string;       // e.g. "vercel-env", "github-actions", "local-env"

  /** Resolve auth context for this consumer type. */
  auth(): Promise<AuthContext>;

  /** Write the new secret value to the target. */
  propagate(target: ConsumerTarget, secret: Secret, ctx: AuthContext): Promise<RotationResult<void>>;

  /** Trigger a redeploy / reload so the target picks up the new value.
   *  Optional — some targets don't need it (local .env). */
  trigger?(target: ConsumerTarget, ctx: AuthContext): Promise<RotationResult<void>>;

  /** Confirm the target is now using the new secret.
   *  Used by grace-period logic. Optional but highly recommended. */
  verify?(target: ConsumerTarget, secret: Secret, ctx: AuthContext): Promise<RotationResult<boolean>>;
}

export interface ConsumerTarget {
  type: string;                  // consumer name — "vercel-env" etc
  params: Record<string, string>; // consumer-specific (project, var_name, repo, etc)
}
```

**Rules:**
- Consumers MUST be idempotent. Calling `propagate` twice with the same value MUST NOT error.
- If `trigger()` is implemented, it must return fast (< 5s). Long-running deploy waits are NOT the consumer's job.
- `verify()` is the basis of grace-period-revoke. If absent, only time-based floor counts.

## Error handling

All async methods return `RotationResult<T>`. Do NOT throw except for programming errors (wrong input types). Expected failures (auth, rate limit, 5xx) go into `result.error`.

## Authentication patterns

### CLI piggyback (preferred)

If the provider has an official CLI (vercel, gh, clerk), read its token from its storage location. Examples:

| Tool | Storage location | Read via |
|---|---|---|
| `vercel` | `~/.local/share/com.vercel.cli/auth.json` | read JSON, extract `token` |
| `gh` | keychain or `~/.config/gh/hosts.yml` | `gh auth token` subprocess |
| `clerk` | `~/.clerk/auth.json` (hypothetical) | read JSON |

Implement `auth()` by reading these. Return `{kind: "cli-piggyback", tool, tokenPath, token}`.

### Encrypted file fallback

For providers without CLI (Resend, Uploadthing, fal, Kapso), use `~/.config/rotate-cli/secrets.age`. The core provides a helper `readEncryptedSecret(name)`.

### Env var

Dev/testing only. Never recommend for production use.

## Testing conventions

Every adapter and consumer MUST have:

1. **Unit tests** in `test/unit/`:
   - Mock HTTP client (`@rotate/core/testing` provides `mockFetch`).
   - Cover happy path + each `AdapterErrorCode` that can occur.

2. **At least 1 integration test** in `test/integration/`:
   - Runs against real provider API with credentials from `ROTATE_TEST_*` env vars.
   - Skips with `test.skipIf(!process.env.ROTATE_TEST_<PROVIDER>)` if creds missing.
   - Uses a dev/test instance, not production.

3. **Snapshot of output envelope** in `test/snapshots/`:
   - Confirms the standard output shape (see `@rotate/core/envelope`).

## Package conventions

- Name: `@rotate/adapter-<provider>` or `@rotate/consumer-<target>`.
- Single default export from `src/index.ts`: an instance of the interface (not a class).
- Types re-exported from `@rotate/core/types`. Do not redeclare.
- No dependencies other than `@rotate/core` and (optionally) a small, well-audited HTTP lib if native fetch is insufficient.
- README.md in the package root with: supported operations, auth setup, config example.

## Reference implementations

- Adapter reference: `packages/adapter-clerk/` — shows CLI piggyback + PLAPI calls.
- Consumer reference: `packages/consumer-vercel-env/` — shows CLI piggyback + env var CRUD + redeploy trigger.

Read both before writing your adapter. Copy structure, adapt endpoints.

## Changes to this spec

Lockdown date: **2026-04-21 Fase 1**. Any change after that requires:
1. PR to this file with rationale.
2. Update to all existing adapters/consumers to conform.
3. Version bump of `@rotate/core` minor.

No drive-by edits.
