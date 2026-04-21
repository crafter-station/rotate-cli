import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ensureStateDirs, stateDir } from "./checkpoints.ts";
import { EXIT, RotateError, makeError } from "./errors.ts";

export interface AgentModeOptions {
  command: string;
  reason?: string;
  yes?: boolean;
  maxRotations?: number;
  auditLog?: string;
  forceRevoke?: boolean;
  skipVerify?: boolean;
  revokeAfter?: string;
  noOwnershipCheck?: boolean;
  forceRotateOther?: boolean;
}

export function isAgentMode(): boolean {
  return process.env.ROTATE_CLI_AGENT_MODE === "1";
}

const MUTATING_COMMANDS = new Set(["apply", "revoke", "rollback", "incident"]);

/** Enforce agent-mode guardrails. Throws RotateError with exit code 5 on violation. */
export function enforceAgentMode(opts: AgentModeOptions): void {
  if (!isAgentMode()) return;
  if (!MUTATING_COMMANDS.has(opts.command)) return;

  if (!opts.reason || opts.reason.trim().length < 5) {
    fail("missing or too short --reason (min 5 chars)");
  }
  if (!opts.yes) fail("--yes required in agent mode");
  if (!opts.auditLog) fail("--audit-log required in agent mode");

  if (opts.command === "apply" || opts.command === "incident") {
    if (opts.maxRotations == null) fail("--max-rotations required in agent mode");
  }
  if (opts.command === "revoke" && !opts.forceRevoke) {
    fail("--force-revoke required in agent mode revoke");
  }
  if (opts.command === "incident" && opts.revokeAfter) {
    fail("--revoke-after forbidden in agent mode (revoke must be explicit)");
  }
  if (opts.skipVerify) fail("--no-verify forbidden in agent mode");

  // Ownership-gate guardrails: agent cannot disable the check entirely.
  if (opts.noOwnershipCheck) {
    fail("--no-ownership-check forbidden in agent mode (gate protects billing)");
  }
  // --force-rotate-other is allowed but requires a longer reason.
  if (opts.forceRotateOther && (opts.reason?.trim().length ?? 0) < 20) {
    fail(
      "--force-rotate-other requires --reason of at least 20 chars explaining the ownership override",
    );
  }

  checkRateLimit();
}

function fail(message: string): never {
  throw new RotateError(
    makeError("invalid_spec", `agent_mode: ${message}`, "rotate-cli"),
    EXIT.AGENT_GUARDRAIL,
  );
}

interface RateLimitState {
  lastRotationAt: number;
}

const RATE_LIMIT_WINDOW_MS = 60_000;

function rateLimitPath(): string {
  return join(stateDir(), "state", "rate-limit.json");
}

function checkRateLimit(): void {
  ensureStateDirs();
  const path = rateLimitPath();
  const now = Date.now();
  let state: RateLimitState = { lastRotationAt: 0 };
  if (existsSync(path)) {
    try {
      state = JSON.parse(readFileSync(path, "utf8")) as RateLimitState;
    } catch {
      /* reset on corrupt */
    }
  }
  const delta = now - state.lastRotationAt;
  if (delta < RATE_LIMIT_WINDOW_MS) {
    fail(`rate_limit: min ${RATE_LIMIT_WINDOW_MS}ms between rotations, ${delta}ms elapsed`);
  }
  writeFileSync(path, JSON.stringify({ lastRotationAt: now }), "utf8");
}

export function assertMaxRotations(count: number, max: number | undefined): void {
  if (!isAgentMode()) return;
  if (max != null && count > max) {
    fail(`selector resolved to ${count} rotations, exceeds --max-rotations=${max}`);
  }
}

export const PER_ROTATION_CONSUMER_CAP = 50;

export function assertConsumerCap(count: number): void {
  if (!isAgentMode()) return;
  if (count > PER_ROTATION_CONSUMER_CAP) {
    fail(`rotation has ${count} consumers, exceeds cap of ${PER_ROTATION_CONSUMER_CAP}`);
  }
}
