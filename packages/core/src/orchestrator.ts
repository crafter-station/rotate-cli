import { appendAudit, generateRotationId, saveCheckpoint } from "./checkpoints.ts";
import { parseDuration } from "./config.ts";
import { RotateError, makeError } from "./errors.ts";
import { getAdapter, getConsumer } from "./registry.ts";
import type {
  AdapterError,
  ConsumerState,
  ConsumerTargetConfig,
  OwnershipPreload,
  PromptIO,
  Rotation,
  Secret,
  SecretConfig,
  SkipReason,
} from "./types.ts";

export interface ApplyOptions {
  reason?: string;
  agentMode?: boolean;
  auditLog?: string;
  parallel?: number;
  skipVerify?: boolean;
  /** Current secret value — used for the ownership check. Injected by the
   *  orchestrator's resolveCurrentValue (commit 2). */
  currentValue?: string;
  /** Pre-warmed per-adapter ownership index (commit 3). */
  ownershipPreload?: OwnershipPreload;
  /** Co-located env vars from the same Vercel project — passed into ownedBy
   *  for sibling-inheritance strategies. */
  coLocatedVars?: Record<string, string>;
  /** Ownership gate behavior. Defaults: skip "other", proceed "unknown". */
  skipUnknown?: boolean;
  forceRotateOther?: boolean;
  noOwnershipCheck?: boolean;
  /** Interactive prompt handle for manual-assist adapters. When the adapter
   *  is mode="manual-assist" this MUST be present and interactive; the
   *  orchestrator rejects the rotation otherwise. */
  io?: PromptIO;
  /** Called as the rotation advances through its pipeline. Wired by the CLI
   *  into the apply progress renderer so the user sees per-rotation stage
   *  transitions (ownership -> create -> propagate -> trigger -> verify). */
  onStep?: (step: "ownership" | "create" | "propagate" | "trigger" | "verify") => void;
  /** Called after each consumer operation finishes within propagate/trigger/
   *  verify so the CLI can show "N/M consumers synced" live. */
  onConsumerProgress?: (progress: {
    step: "propagate" | "trigger" | "verify";
    done: number;
    total: number;
  }) => void;
}

export interface ApplyResult {
  rotation: Rotation;
  envelopeStatus: "success" | "partial" | "error" | "skipped";
}

/** Run the create + propagate + verify pipeline. Does NOT revoke. */
export async function applyRotation(
  secret: SecretConfig,
  opts: ApplyOptions = {},
): Promise<ApplyResult> {
  const adapter = getAdapter(secret.adapter);
  if (!adapter) {
    throw new RotateError(
      makeError("invalid_spec", `unknown adapter: ${secret.adapter}`, "rotate-cli"),
      1,
    );
  }

  const rotation: Rotation = {
    id: generateRotationId(),
    secretId: secret.id,
    adapter: secret.adapter,
    status: "in_progress",
    startedAt: new Date().toISOString(),
    reason: opts.reason,
    consumers: secret.consumers.map((target) => ({
      target: { type: target.type, params: target.params },
      status: "pending",
    })),
    errors: [],
    agentMode: opts.agentMode ?? false,
  };

  saveCheckpoint({
    rotationId: rotation.id,
    rotation,
    stepCompleted: "none",
    savedAt: new Date().toISOString(),
  });

  // Step 0: Ownership gate (optional, opt-out via opts.noOwnershipCheck).
  opts.onStep?.("ownership");
  const authCtx = await adapter.auth();
  if (adapter.ownedBy && !opts.noOwnershipCheck && opts.currentValue) {
    try {
      const ownership = await adapter.ownedBy(opts.currentValue, authCtx, {
        coLocatedVars: opts.coLocatedVars,
        preload: opts.ownershipPreload,
      });
      rotation.ownership = ownership;

      const skipReason = decideSkip(ownership, opts);
      if (skipReason) {
        rotation.status = "skipped";
        rotation.skipReason = skipReason;
        saveCheckpoint({
          rotationId: rotation.id,
          rotation,
          stepCompleted: "none",
          savedAt: new Date().toISOString(),
        });
        audit(opts.auditLog, rotation);
        return { rotation, envelopeStatus: "skipped" };
      }
    } catch (cause) {
      // Gate failure should not block rotation — fall back to "unknown" behavior.
      rotation.errors.push(
        makeError("provider_error", `ownership check failed: ${String(cause)}`, secret.adapter, {
          retryable: true,
          cause,
        }),
      );
    }
  } else if (adapter.ownedBy && !opts.noOwnershipCheck && !opts.currentValue) {
    // Current value unavailable — treat like "unknown" verdict.
    if (opts.skipUnknown) {
      rotation.status = "skipped";
      rotation.skipReason = {
        kind: "ownership-current-value-unavailable",
        evidence: `current value for ${secret.id} unavailable; set secrets[].currentValueEnv or disable with --no-ownership-check`,
      };
      saveCheckpoint({
        rotationId: rotation.id,
        rotation,
        stepCompleted: "none",
        savedAt: new Date().toISOString(),
      });
      audit(opts.auditLog, rotation);
      return { rotation, envelopeStatus: "skipped" };
    }
  }

  // Manual-assist gate: adapter requires interactive input, can't run
  // unattended. Reject early with a clear error instead of hanging in the
  // provider SDK.
  const mode = adapter.mode ?? "auto";
  if (mode === "manual-assist") {
    if (opts.agentMode) {
      rotation.status = "failed";
      rotation.errors.push(
        makeError(
          "unsupported",
          `adapter ${secret.adapter} is manual-assist and cannot run in agent mode`,
          secret.adapter,
          { retryable: false },
        ),
      );
      audit(opts.auditLog, rotation);
      return { rotation, envelopeStatus: "error" };
    }
    if (!opts.io?.isInteractive) {
      rotation.status = "failed";
      rotation.errors.push(
        makeError(
          "unsupported",
          `adapter ${secret.adapter} requires an interactive terminal — re-run with --manual-only from a TTY`,
          secret.adapter,
          { retryable: false },
        ),
      );
      audit(opts.auditLog, rotation);
      return { rotation, envelopeStatus: "error" };
    }
  }

  // Step 1: Create.
  opts.onStep?.("create");
  const createResult = await adapter.create(
    {
      secretId: secret.id,
      adapter: secret.adapter,
      metadata: secret.metadata ?? {},
      reason: opts.reason,
      io: mode === "manual-assist" ? opts.io : undefined,
    },
    authCtx,
  );
  if (!createResult.ok || !createResult.data) {
    rotation.status = "failed";
    rotation.errors.push(
      createResult.error ?? makeError("provider_error", "create failed", secret.adapter),
    );
    saveCheckpoint({
      rotationId: rotation.id,
      rotation,
      stepCompleted: "none",
      savedAt: new Date().toISOString(),
    });
    audit(opts.auditLog, rotation);
    return { rotation, envelopeStatus: "error" };
  }
  rotation.newSecret = createResult.data;
  saveCheckpoint({
    rotationId: rotation.id,
    rotation,
    stepCompleted: "create",
    savedAt: new Date().toISOString(),
  });

  // Step 2: Propagate (parallel fail-fast).
  opts.onStep?.("propagate");
  await propagateAll(rotation, opts.parallel ?? 10, opts.onConsumerProgress);
  saveCheckpoint({
    rotationId: rotation.id,
    rotation,
    stepCompleted: "propagate",
    savedAt: new Date().toISOString(),
  });

  // Step 3: Trigger redeploys (parallel, best-effort).
  opts.onStep?.("trigger");
  await triggerAll(rotation, opts.onConsumerProgress);
  saveCheckpoint({
    rotationId: rotation.id,
    rotation,
    stepCompleted: "trigger",
    savedAt: new Date().toISOString(),
  });

  // Step 4: Verify adapter-side + consumer-side.
  opts.onStep?.("verify");
  if (!opts.skipVerify) {
    const adapterVerify = await adapter.verify(rotation.newSecret, authCtx);
    if (!adapterVerify.ok) {
      rotation.status = "failed";
      rotation.errors.push(
        adapterVerify.error ?? makeError("provider_error", "adapter verify failed", secret.adapter),
      );
      saveCheckpoint({
        rotationId: rotation.id,
        rotation,
        stepCompleted: "verify",
        savedAt: new Date().toISOString(),
      });
      audit(opts.auditLog, rotation);
      return { rotation, envelopeStatus: "error" };
    }
    await verifyAllConsumers(rotation, opts.onConsumerProgress);
  }

  rotation.status = "in_grace";
  rotation.gracePeriodEndsAt = new Date(Date.now() + parseDuration("1h")).toISOString();
  saveCheckpoint({
    rotationId: rotation.id,
    rotation,
    stepCompleted: "verify",
    savedAt: new Date().toISOString(),
  });
  audit(opts.auditLog, rotation);

  const hasFailures = rotation.consumers.some((c) => c.status === "failed");
  return {
    rotation,
    envelopeStatus: hasFailures ? "partial" : "success",
  };
}

async function propagateAll(
  rotation: Rotation,
  parallel: number,
  onConsumerProgress?: ApplyOptions["onConsumerProgress"],
): Promise<void> {
  if (!rotation.newSecret) return;
  const total = rotation.consumers.length;
  let done = 0;
  const tasks = rotation.consumers.map((state) => async () => {
    await propagateOne(rotation, state, rotation.newSecret!);
    done++;
    onConsumerProgress?.({ step: "propagate", done, total });
  });
  await runPool(tasks, parallel);
}

async function propagateOne(
  rotation: Rotation,
  state: ConsumerState,
  secret: Secret,
): Promise<void> {
  const consumer = getConsumer(state.target.type);
  if (!consumer) {
    state.status = "failed";
    state.error = makeError("invalid_spec", `unknown consumer: ${state.target.type}`, "rotate-cli");
    return;
  }
  try {
    const ctx = await consumer.auth();
    const result = await consumer.propagate(state.target, secret, ctx);
    if (!result.ok) {
      state.status = "failed";
      state.error = result.error;
      return;
    }
    state.status = "propagated";
    state.propagatedAt = new Date().toISOString();
  } catch (cause) {
    state.status = "failed";
    state.error = makeError("provider_error", String(cause), consumer.name, { cause });
  }
}

async function triggerAll(
  rotation: Rotation,
  onConsumerProgress?: ApplyOptions["onConsumerProgress"],
): Promise<void> {
  const total = rotation.consumers.length;
  let done = 0;
  for (const state of rotation.consumers) {
    if (state.status !== "propagated") {
      done++;
      onConsumerProgress?.({ step: "trigger", done, total });
      continue;
    }
    const consumer = getConsumer(state.target.type);
    if (!consumer?.trigger) {
      state.status = "triggered"; // no-op triggers count as done
      done++;
      onConsumerProgress?.({ step: "trigger", done, total });
      continue;
    }
    try {
      const ctx = await consumer.auth();
      const result = await consumer.trigger(state.target, ctx);
      if (result.ok) state.status = "triggered";
      else {
        state.error = result.error;
      }
    } catch (cause) {
      state.error = makeError("provider_error", String(cause), consumer.name, { cause });
    }
    done++;
    onConsumerProgress?.({ step: "trigger", done, total });
  }
}

async function verifyAllConsumers(
  rotation: Rotation,
  onConsumerProgress?: ApplyOptions["onConsumerProgress"],
): Promise<void> {
  if (!rotation.newSecret) return;
  const total = rotation.consumers.length;
  let done = 0;
  for (const state of rotation.consumers) {
    if (state.status !== "triggered" && state.status !== "propagated") {
      done++;
      onConsumerProgress?.({ step: "verify", done, total });
      continue;
    }
    const consumer = getConsumer(state.target.type);
    if (!consumer?.verify) {
      // No verify — optimistically mark synced.
      state.status = "synced";
      state.verifiedAt = new Date().toISOString();
      done++;
      onConsumerProgress?.({ step: "verify", done, total });
      continue;
    }
    try {
      const ctx = await consumer.auth();
      const result = await consumer.verify(state.target, rotation.newSecret, ctx);
      if (result.ok && result.data) {
        state.status = "synced";
        state.verifiedAt = new Date().toISOString();
      }
    } catch {
      /* keep status as-is, verify is best-effort for now */
    }
    done++;
    onConsumerProgress?.({ step: "verify", done, total });
  }
}

async function runPool(tasks: Array<() => Promise<void>>, concurrency: number): Promise<void> {
  const queue = [...tasks];
  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.min(concurrency, queue.length); i++) {
    workers.push(
      (async () => {
        while (queue.length) {
          const task = queue.shift();
          if (task) await task();
        }
      })(),
    );
  }
  await Promise.all(workers);
}

function audit(path: string | undefined, rotation: Rotation): void {
  appendAudit(path, {
    timestamp: new Date().toISOString(),
    rotation_id: rotation.id,
    secret_id: rotation.secretId,
    adapter: rotation.adapter,
    status: rotation.status,
    agent_mode: rotation.agentMode,
    reason: rotation.reason,
    consumers: rotation.consumers.map((c) => ({
      type: c.target.type,
      params: c.target.params,
      status: c.status,
    })),
    errors: rotation.errors,
  });
}

/** Revoke the OLD secret for a rotation in grace. */
export async function revokeRotation(
  rotation: Rotation,
  opts: {
    force?: boolean;
    agentMode?: boolean;
    reason?: string;
    auditLog?: string;
    io?: PromptIO;
  } = {},
): Promise<{ ok: boolean; errors: AdapterError[] }> {
  if (rotation.status !== "in_grace") {
    return {
      ok: false,
      errors: [
        makeError("invalid_spec", `rotation not in grace: ${rotation.status}`, "rotate-cli"),
      ],
    };
  }
  const allSynced = rotation.consumers.every((c) => c.status === "synced");
  if (!allSynced && !opts.force) {
    return {
      ok: false,
      errors: [makeError("invalid_spec", "consumers not fully synced; use --force", "rotate-cli")],
    };
  }
  const adapter = getAdapter(rotation.adapter);
  if (!adapter || !rotation.oldSecret) {
    return {
      ok: false,
      errors: [makeError("invalid_spec", "no old secret or adapter", "rotate-cli")],
    };
  }
  const mode = adapter.mode ?? "auto";
  if (mode === "manual-assist") {
    if (opts.agentMode) {
      return {
        ok: false,
        errors: [
          makeError(
            "unsupported",
            `adapter ${rotation.adapter} is manual-assist and cannot revoke in agent mode`,
            rotation.adapter,
            { retryable: false },
          ),
        ],
      };
    }
    if (!opts.io?.isInteractive) {
      return {
        ok: false,
        errors: [
          makeError(
            "unsupported",
            `adapter ${rotation.adapter} requires an interactive terminal to revoke`,
            rotation.adapter,
            { retryable: false },
          ),
        ],
      };
    }
  }
  const ctx = await adapter.auth();
  const result = await adapter.revoke(rotation.oldSecret, ctx, {
    io: mode === "manual-assist" ? opts.io : undefined,
  });
  if (!result.ok) return { ok: false, errors: [result.error!] };
  rotation.status = "revoked";
  audit(opts.auditLog, rotation);
  return { ok: true, errors: [] };
}

/**
 * Run preloadOwnership() once per unique adapter referenced by `secrets`.
 * Returns a Map<adapterName, preload> the caller passes back to each
 * applyRotation() as `opts.ownershipPreload`.
 *
 * Adapters without preloadOwnership are skipped — they answer ownership
 * questions with O(1) calls per check and don't benefit from warming.
 *
 * Errors in a single provider's preload do NOT abort the others. Failures
 * are captured in `errors` and the Map entry is simply absent.
 */
export async function preloadOwnershipForSecrets(secrets: SecretConfig[]): Promise<{
  map: Map<string, OwnershipPreload>;
  errors: Map<string, string>;
}> {
  const uniqueProviders = [...new Set(secrets.map((s) => s.adapter))];
  const map = new Map<string, OwnershipPreload>();
  const errors = new Map<string, string>();

  await Promise.all(
    uniqueProviders.map(async (name) => {
      const adapter = getAdapter(name);
      if (!adapter?.preloadOwnership) return;
      try {
        const ctx = await adapter.auth();
        const preload = await adapter.preloadOwnership(ctx);
        map.set(name, preload);
      } catch (cause) {
        errors.set(name, String(cause));
      }
    }),
  );

  return { map, errors };
}

/**
 * Decide whether an ownership verdict should skip the rotation.
 * Returns `null` when the rotation should proceed.
 */
export function decideSkip(
  ownership: import("./types.ts").OwnershipResult,
  opts: Pick<ApplyOptions, "skipUnknown" | "forceRotateOther">,
): SkipReason | null {
  if (ownership.verdict === "other" && !opts.forceRotateOther) {
    return {
      kind: "ownership-other",
      evidence: ownership.evidence,
    };
  }
  if (ownership.verdict === "self" && !ownership.adminCanBill) {
    return {
      kind: "ownership-self-member-only",
      evidence: `${ownership.evidence} (your role: ${ownership.teamRole ?? "member"})`,
    };
  }
  if (ownership.verdict === "unknown" && opts.skipUnknown) {
    return {
      kind: "ownership-unknown-skipped",
      evidence: ownership.evidence,
    };
  }
  return null;
}
