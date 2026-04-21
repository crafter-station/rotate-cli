/** Core types for rotate-cli. See docs/ADAPTER_SPEC.md for rationale. */

export interface Secret {
  id: string;
  provider: string;
  value: string;
  metadata: Record<string, string>;
  createdAt: string;
  expiresAt?: string;
}

export type AuthContext =
  | { kind: "cli-piggyback"; tool: string; tokenPath?: string; token: string }
  | { kind: "encrypted-file"; path: string; token: string }
  | { kind: "env"; varName: string; token: string };

export interface AuthStoredCredential {
  token: string;
  updatedAt: string;
  source: "manual";
}

export interface AuthSummary {
  name: string;
  displayName: string;
  envVars: string[];
  setupUrl?: string;
  notes?: string[];
}

export interface AuthListEntry {
  name: string;
  displayName: string;
  status: "configured" | "missing";
  source: "env" | "stored" | "none";
  envVars: string[];
  setupUrl?: string;
  usedBy: Array<{ kind: "adapter" | "consumer"; name: string }>;
}

export interface PromptChoice {
  label: string;
  value: string;
  hint?: string;
}

export interface PromptConfirmOptions {
  initialValue?: boolean;
}

export interface PromptStepNote {
  kind: "note";
  message: string;
}

export interface PromptStepText {
  kind: "text";
  name: string;
  message: string;
  placeholder?: string;
  initialValue?: string;
}

export interface PromptStepPassword {
  kind: "password";
  name: string;
  message: string;
  mask?: string;
}

export interface PromptStepSelect {
  kind: "select";
  name: string;
  message: string;
  choices: PromptChoice[];
}

export interface PromptStepConfirm {
  kind: "confirm";
  name: string;
  message: string;
  initialValue?: boolean;
}

export type PromptStep =
  | PromptStepNote
  | PromptStepText
  | PromptStepPassword
  | PromptStepSelect
  | PromptStepConfirm;

export type PromptAnswers = Record<string, string | boolean>;

export interface PromptIO {
  readonly isInteractive: boolean;
  note(message: string): void;
  promptLine(message: string): Promise<string>;
  promptSecret(message: string): Promise<string>;
  select(message: string, choices: PromptChoice[]): Promise<string>;
  confirm(message: string, options?: PromptConfirmOptions): Promise<boolean>;
  close(): Promise<void>;
}

export interface AuthMethodDefinition {
  readonly id: string;
  readonly label: string;
  readonly description?: string;
  readonly steps: PromptStep[];
  submit(answers: PromptAnswers, io: PromptIO): Promise<AuthContext>;
}

export interface AuthDefinition {
  readonly name: string;
  readonly displayName: string;
  readonly envVars: string[];
  readonly setupUrl?: string;
  readonly notes?: string[];
  readonly methods?: AuthMethodDefinition[];
  resolve(): Promise<AuthContext>;
  login(io: PromptIO): Promise<AuthContext>;
  logout?(): Promise<boolean>;
  verify?(ctx: AuthContext): Promise<void>;
}

export interface RotationSpec {
  secretId: string;
  adapter: string;
  metadata: Record<string, string>;
  reason?: string;
}

export interface RotationResult<T = Secret> {
  ok: boolean;
  data?: T;
  error?: AdapterError;
}

export type AdapterErrorCode =
  | "auth_failed"
  | "rate_limited"
  | "not_found"
  | "provider_error"
  | "network_error"
  | "invalid_spec"
  | "unsupported";

export interface AdapterError {
  code: AdapterErrorCode;
  message: string;
  provider: string;
  retryable: boolean;
  cause?: unknown;
}

export interface Adapter {
  readonly name: string;
  readonly authRef?: string;
  readonly authDefinition?: AuthDefinition;
  auth(): Promise<AuthContext>;
  create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>>;
  verify(secret: Secret, ctx: AuthContext): Promise<RotationResult<boolean>>;
  revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>>;
  list?(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>>;

  /**
   * Determine whether `secretValue` belongs to the account/org/workspace
   * authenticated by `ctx`, BEFORE attempting rotation. Optional — adapters
   * without a feasible strategy omit this method and the orchestrator
   * treats the answer as `unknown`.
   *
   * `coLocatedVars` carries sibling env-vars from the same Vercel project
   * (e.g. SUPABASE_URL is co-located with SUPABASE_SERVICE_ROLE_KEY). Adapters
   * use it for sibling-inheritance strategies that avoid network calls.
   *
   * `preload` (returned from `preloadOwnership`, if present) holds the warm
   * reverse-index built once per session — list of databases, projects, team
   * ids, etc. Pass through to every ownership check.
   */
  ownedBy?(
    secretValue: string,
    ctx: AuthContext,
    opts?: OwnershipOptions,
  ): Promise<OwnershipResult>;

  /**
   * Build a reusable snapshot of the admin's resources (orgs, projects,
   * databases, installations) that `ownedBy` can consult without making
   * N calls per secret. Called once per `rotate` invocation, cached in
   * `adminCtx` and fanned out to every subsequent ownership check.
   *
   * Adapters with 1-call introspection (OpenAI, Vercel token) can omit
   * this — they hit their endpoint fresh per check since the cost is O(1)
   * anyway.
   */
  preloadOwnership?(ctx: AuthContext): Promise<OwnershipPreload>;
}

export interface OwnershipOptions {
  coLocatedVars?: Record<string, string>;
  preload?: OwnershipPreload;
}

export type OwnershipPreload = Record<string, unknown>;

export type OwnershipVerdict = "self" | "other" | "unknown";

export interface OwnershipResult {
  verdict: OwnershipVerdict;
  /**
   * Whether the admin has billing/management control of the secret. May be
   * `false` even when `verdict === "self"` (e.g. user is a member but not
   * admin of the GitHub org that holds an installation token).
   */
  adminCanBill: boolean;
  scope?: "user" | "team" | "org" | "project";
  teamRole?: "admin" | "member" | "viewer";
  confidence: "high" | "medium" | "low";
  /** Human-readable evidence string for audit logs and CLI output. */
  evidence: string;
  /** Strategy used, for telemetry/debugging. */
  strategy: "format-decode" | "api-introspection" | "list-match" | "sibling-inheritance" | "prompt";
}

export interface ConsumerTarget {
  type: string;
  params: Record<string, string>;
}

export interface Consumer {
  readonly name: string;
  readonly authRef?: string;
  auth(): Promise<AuthContext>;
  propagate(
    target: ConsumerTarget,
    secret: Secret,
    ctx: AuthContext,
  ): Promise<RotationResult<void>>;
  trigger?(target: ConsumerTarget, ctx: AuthContext): Promise<RotationResult<void>>;
  verify?(
    target: ConsumerTarget,
    secret: Secret,
    ctx: AuthContext,
  ): Promise<RotationResult<boolean>>;
}

export interface SecretConfig {
  id: string;
  adapter: string;
  metadata?: Record<string, string>;
  tags?: string[];
  consumers: ConsumerTargetConfig[];
}

export interface ConsumerTargetConfig {
  type: string;
  params: Record<string, string>;
}

export interface RotateConfig {
  version: 1;
  defaults?: {
    grace_period_floor?: string;
  };
  secrets: SecretConfig[];
}

export interface IncidentFile {
  version: 1;
  id: string;
  published?: string;
  reference?: string;
  severity?: "low" | "medium" | "high" | "critical";
  scope: IncidentScope[];
}

export interface IncidentScope {
  provider: string;
  filter?: Record<string, string>;
}

export interface Rotation {
  id: string;
  secretId: string;
  adapter: string;
  status: RotationStatus;
  startedAt: string;
  gracePeriodEndsAt?: string;
  reason?: string;
  oldSecret?: Secret;
  newSecret?: Secret;
  consumers: ConsumerState[];
  errors: AdapterError[];
  agentMode: boolean;
}

export type RotationStatus = "in_progress" | "in_grace" | "revoked" | "rolled_back" | "failed";

export interface ConsumerState {
  target: ConsumerTarget;
  status: "pending" | "propagated" | "triggered" | "synced" | "failed";
  error?: AdapterError;
  propagatedAt?: string;
  verifiedAt?: string;
}

export interface Checkpoint {
  rotationId: string;
  rotation: Rotation;
  stepCompleted: "create" | "propagate" | "trigger" | "verify" | "none";
  savedAt: string;
}
