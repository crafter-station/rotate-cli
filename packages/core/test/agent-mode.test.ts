import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertConsumerCap,
  assertMaxRotations,
  enforceAgentMode,
  isAgentMode,
} from "../src/agent-mode.ts";
import { RotateError } from "../src/errors.ts";

describe("agent-mode", () => {
  let stateDir: string;
  beforeEach(() => {
    stateDir = mkdtempSync(join(tmpdir(), "rotate-cli-agent-"));
    process.env.ROTATE_CLI_STATE_DIR = stateDir;
  });
  afterEach(() => {
    delete process.env.ROTATE_CLI_AGENT_MODE;
    delete process.env.ROTATE_CLI_STATE_DIR;
    rmSync(stateDir, { recursive: true, force: true });
  });

  test("disabled by default", () => {
    expect(isAgentMode()).toBe(false);
  });

  test("activates via env var", () => {
    process.env.ROTATE_CLI_AGENT_MODE = "1";
    expect(isAgentMode()).toBe(true);
  });

  test("apply requires --reason, --yes, --audit-log, --max-rotations", () => {
    process.env.ROTATE_CLI_AGENT_MODE = "1";
    expect(() => enforceAgentMode({ command: "apply" })).toThrow(RotateError);
    expect(() => enforceAgentMode({ command: "apply", reason: "valid-reason" })).toThrow(/--yes/);
    expect(() => enforceAgentMode({ command: "apply", reason: "valid-reason", yes: true })).toThrow(
      /--audit-log/,
    );
    expect(() =>
      enforceAgentMode({
        command: "apply",
        reason: "valid-reason",
        yes: true,
        auditLog: "/tmp/x.jsonl",
      }),
    ).toThrow(/--max-rotations/);
  });

  test("apply happy-path enforces rate limit second call", () => {
    process.env.ROTATE_CLI_AGENT_MODE = "1";
    const opts = {
      command: "apply",
      reason: "valid-reason",
      yes: true,
      auditLog: "/tmp/audit.jsonl",
      maxRotations: 1,
    };
    // First call ok.
    enforceAgentMode(opts);
    // Second within a minute should throw rate_limit.
    expect(() => enforceAgentMode(opts)).toThrow(/rate_limit/);
  });

  test("skipVerify forbidden", () => {
    process.env.ROTATE_CLI_AGENT_MODE = "1";
    expect(() =>
      enforceAgentMode({
        command: "apply",
        reason: "valid-reason",
        yes: true,
        auditLog: "/tmp/x.jsonl",
        maxRotations: 1,
        skipVerify: true,
      }),
    ).toThrow(/no-verify/);
  });

  test("revoke requires --force-revoke", () => {
    process.env.ROTATE_CLI_AGENT_MODE = "1";
    expect(() =>
      enforceAgentMode({
        command: "revoke",
        reason: "valid-reason",
        yes: true,
        auditLog: "/tmp/x.jsonl",
      }),
    ).toThrow(/--force-revoke/);
  });

  test("assertMaxRotations enforces cap in agent mode", () => {
    process.env.ROTATE_CLI_AGENT_MODE = "1";
    expect(() => assertMaxRotations(6, 5)).toThrow(/exceeds/);
    expect(() => assertMaxRotations(5, 5)).not.toThrow();
  });

  test("assertConsumerCap blocks > 50", () => {
    process.env.ROTATE_CLI_AGENT_MODE = "1";
    expect(() => assertConsumerCap(51)).toThrow();
    expect(() => assertConsumerCap(50)).not.toThrow();
  });

  test("non-agent-mode skips all checks", () => {
    expect(() =>
      enforceAgentMode({
        command: "apply",
        // missing everything
      }),
    ).not.toThrow();
  });

  test("--no-ownership-check forbidden in agent mode", () => {
    process.env.ROTATE_CLI_AGENT_MODE = "1";
    expect(() =>
      enforceAgentMode({
        command: "apply",
        reason: "valid-reason-here",
        yes: true,
        auditLog: "/tmp/audit.jsonl",
        maxRotations: 1,
        noOwnershipCheck: true,
      }),
    ).toThrow(/--no-ownership-check/);
  });

  test("--force-rotate-other requires 20+ char reason in agent mode", () => {
    process.env.ROTATE_CLI_AGENT_MODE = "1";
    expect(() =>
      enforceAgentMode({
        command: "apply",
        reason: "too short",
        yes: true,
        auditLog: "/tmp/audit.jsonl",
        maxRotations: 1,
        forceRotateOther: true,
      }),
    ).toThrow(/20 chars/);
  });

  test("--force-rotate-other allowed with long reason", () => {
    process.env.ROTATE_CLI_AGENT_MODE = "1";
    expect(() =>
      enforceAgentMode({
        command: "apply",
        reason: "rotating anthony's keys because we split ownership today",
        yes: true,
        auditLog: "/tmp/audit.jsonl",
        maxRotations: 1,
        forceRotateOther: true,
      }),
    ).not.toThrow();
  });
});
