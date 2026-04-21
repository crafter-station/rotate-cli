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
  auth(): Promise<AuthContext>;
  create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>>;
  verify(secret: Secret, ctx: AuthContext): Promise<RotationResult<boolean>>;
  revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>>;
  list?(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>>;
}

export interface ConsumerTarget {
  type: string;
  params: Record<string, string>;
}

export interface Consumer {
  readonly name: string;
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
