import { Command } from "commander";
import { assertMaxRotations, enforceAgentMode, isAgentMode } from "./agent-mode.ts";
import {
  appendAudit,
  archiveToHistory,
  ensureStateDirs,
  listCheckpoints,
  loadCheckpoint,
  saveCheckpoint,
} from "./checkpoints.ts";
import { loadConfig, loadIncident, selectByIncident, selectByQuery } from "./config.ts";
import { emit, makeEnvelope } from "./envelope.ts";
import { EXIT, RotateError } from "./errors.ts";
import { applyRotation, revokeRotation } from "./orchestrator.ts";
import { listAdapters, listConsumers } from "./registry.ts";

export async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program
    .name("rotate")
    .description("Agent-first secrets rotation CLI")
    .version("0.0.1")
    .option("--json", "force JSON output")
    .option("--pretty", "force human output")
    .option("-y, --yes", "skip confirmation prompts")
    .option("--config <path>", "path to rotate.config.yaml", "./rotate.config.yaml")
    .option("--reason <string>", "justification (required in agent mode)")
    .option("--audit-log <path>", "append-only audit log path");

  program
    .command("init")
    .description("create state dirs and starter config")
    .action(() => {
      ensureStateDirs();
      const started = Date.now();
      emit(
        makeEnvelope({
          command: "init",
          status: "success",
          startedAt: started,
          agentMode: isAgentMode(),
          data: { state_dir: process.env.ROTATE_CLI_STATE_DIR ?? "~/.config/rotate-cli" },
          next_actions: [
            "Create `rotate.config.yaml` in your repo",
            "Run `rotate doctor` to verify adapter auth",
          ],
        }),
        EXIT.OK,
      );
    });

  program
    .command("doctor")
    .description("verify auth for all registered adapters/consumers")
    .action(async () => {
      const started = Date.now();
      const rows: Array<{ kind: string; name: string; ok: boolean; error?: string }> = [];
      for (const adapter of listAdapters()) {
        try {
          await adapter.auth();
          rows.push({ kind: "adapter", name: adapter.name, ok: true });
        } catch (err) {
          rows.push({ kind: "adapter", name: adapter.name, ok: false, error: String(err) });
        }
      }
      for (const consumer of listConsumers()) {
        try {
          await consumer.auth();
          rows.push({ kind: "consumer", name: consumer.name, ok: true });
        } catch (err) {
          rows.push({ kind: "consumer", name: consumer.name, ok: false, error: String(err) });
        }
      }
      const failing = rows.filter((r) => !r.ok);
      emit(
        makeEnvelope({
          command: "doctor",
          status: failing.length ? "partial" : "success",
          startedAt: started,
          agentMode: isAgentMode(),
          data: { rows },
          next_actions: failing.length
            ? failing.map((f) => `Fix auth for ${f.kind} ${f.name}: ${f.error}`)
            : ["All adapters and consumers authenticated"],
        }),
        failing.length ? EXIT.PROVIDER_ERROR : EXIT.OK,
      );
    });

  program
    .command("plan")
    .argument("[selector...]", "secret identifiers (optional; use --provider/--tag for queries)")
    .option("--provider <name>")
    .option("--tag <name>")
    .action((ids: string[] | undefined, opts: { provider?: string; tag?: string }) => {
      const started = Date.now();
      const config = loadConfig(program.opts().config);
      const selected = selectByQuery(config, {
        ids: ids ?? [],
        provider: opts.provider,
        tag: opts.tag,
      });
      emit(
        makeEnvelope({
          command: "plan",
          status: "success",
          startedAt: started,
          agentMode: isAgentMode(),
          data: {
            selected: selected.map((s) => ({
              id: s.id,
              adapter: s.adapter,
              consumer_count: s.consumers.length,
              consumers: s.consumers,
            })),
          },
          next_actions: selected.length
            ? [`Run \`rotate apply ${(ids ?? []).join(" ")} --yes --reason "..."\` to execute`]
            : ["Selector matched no secrets — check rotate.config.yaml"],
        }),
        selected.length ? EXIT.OK : EXIT.USER_ERROR,
      );
    });

  program
    .command("apply")
    .argument("[selector...]", "secret identifiers (optional with --provider/--tag)")
    .option("--provider <name>")
    .option("--tag <name>")
    .option("--max-rotations <n>", "hard cap on rotations", (v) => Number.parseInt(v, 10))
    .option("--parallel <n>", "consumer propagation concurrency", (v) => Number.parseInt(v, 10), 10)
    .option("--no-verify", "skip verify step (forbidden in agent mode)")
    .action(
      async (
        idsArg: string[] | undefined,
        opts: {
          provider?: string;
          tag?: string;
          maxRotations?: number;
          parallel: number;
          verify: boolean;
        },
      ) => {
        const ids = idsArg ?? [];
        const started = Date.now();
        const globalOpts = program.opts();
        enforceAgentMode({
          command: "apply",
          reason: globalOpts.reason,
          yes: globalOpts.yes,
          maxRotations: opts.maxRotations,
          auditLog: globalOpts.auditLog,
          skipVerify: opts.verify === false,
        });
        const config = loadConfig(globalOpts.config);
        const selected = selectByQuery(config, { ids, provider: opts.provider, tag: opts.tag });
        assertMaxRotations(selected.length, opts.maxRotations);
        if (!selected.length) {
          emit(
            makeEnvelope({
              command: "apply",
              status: "error",
              startedAt: started,
              agentMode: isAgentMode(),
              errors: [
                {
                  code: "invalid_spec",
                  message: "selector matched no secrets",
                  provider: "rotate-cli",
                  retryable: false,
                },
              ],
            }),
            EXIT.USER_ERROR,
          );
          return;
        }
        const results = [];
        for (const secret of selected) {
          const r = await applyRotation(secret, {
            reason: globalOpts.reason,
            agentMode: isAgentMode(),
            auditLog: globalOpts.auditLog,
            parallel: opts.parallel,
            skipVerify: opts.verify === false,
          });
          results.push(r);
        }
        const anyError = results.some((r) => r.envelopeStatus === "error");
        const anyPartial = results.some((r) => r.envelopeStatus === "partial");
        const status = anyError ? "error" : anyPartial ? "partial" : "success";
        const nextActions = results
          .filter((r) => r.rotation.status === "in_grace")
          .map(
            (r) =>
              `Run \`rotate status ${r.rotation.id} --json\` to check sync; \`rotate revoke ${r.rotation.id}\` when ready`,
          );
        emit(
          makeEnvelope({
            command: "apply",
            status,
            startedAt: started,
            agentMode: isAgentMode(),
            data: {
              rotations: results.map((r) => ({
                rotation_id: r.rotation.id,
                secret_id: r.rotation.secretId,
                status: r.rotation.status,
                grace_period_ends: r.rotation.gracePeriodEndsAt,
                consumers: r.rotation.consumers.map((c) => ({
                  target: c.target,
                  status: c.status,
                  error: c.error,
                })),
              })),
            },
            next_actions: nextActions,
          }),
          anyError ? EXIT.PROVIDER_ERROR : anyPartial ? EXIT.IN_GRACE_WARNING : EXIT.OK,
        );
      },
    );

  program
    .command("status")
    .argument("[rotation-id]")
    .action((rotationId?: string) => {
      const started = Date.now();
      const checkpoints = listCheckpoints();
      if (rotationId) {
        const c = loadCheckpoint(rotationId);
        if (!c) {
          emit(
            makeEnvelope({
              command: "status",
              status: "error",
              startedAt: started,
              agentMode: isAgentMode(),
              errors: [
                {
                  code: "not_found",
                  message: `rotation ${rotationId} not found`,
                  provider: "rotate-cli",
                  retryable: false,
                },
              ],
            }),
            EXIT.USER_ERROR,
          );
          return;
        }
        const pending = c.rotation.consumers.some((s) => s.status !== "synced");
        emit(
          makeEnvelope({
            command: "status",
            status: "success",
            startedAt: started,
            agentMode: isAgentMode(),
            data: { rotation: c.rotation, step_completed: c.stepCompleted },
            next_actions: pending
              ? [
                  "Consumers still syncing; check again or inspect",
                  `Run \`rotate history ${rotationId}\` for log`,
                ]
              : [`All consumers synced; run \`rotate revoke ${rotationId}\` to close`],
          }),
          pending ? EXIT.IN_GRACE_WARNING : EXIT.OK,
        );
        return;
      }
      emit(
        makeEnvelope({
          command: "status",
          status: "success",
          startedAt: started,
          agentMode: isAgentMode(),
          data: {
            in_flight: checkpoints.map((c) => ({
              rotation_id: c.rotationId,
              secret_id: c.rotation.secretId,
              status: c.rotation.status,
              step_completed: c.stepCompleted,
              grace_period_ends: c.rotation.gracePeriodEndsAt,
            })),
          },
          next_actions: checkpoints.length
            ? [`${checkpoints.length} rotation(s) in flight; inspect via \`rotate status <id>\``]
            : ["No rotations in flight"],
        }),
        EXIT.OK,
      );
    });

  program
    .command("revoke")
    .argument("<rotation-id>")
    .option("--force-revoke", "revoke even if consumers not synced")
    .action(async (rotationId: string, opts: { forceRevoke?: boolean }) => {
      const started = Date.now();
      const globalOpts = program.opts();
      enforceAgentMode({
        command: "revoke",
        reason: globalOpts.reason,
        yes: globalOpts.yes,
        auditLog: globalOpts.auditLog,
        forceRevoke: opts.forceRevoke,
      });
      const c = loadCheckpoint(rotationId);
      if (!c) {
        emit(
          makeEnvelope({
            command: "revoke",
            status: "error",
            startedAt: started,
            agentMode: isAgentMode(),
            errors: [
              {
                code: "not_found",
                message: `rotation ${rotationId} not found`,
                provider: "rotate-cli",
                retryable: false,
              },
            ],
          }),
          EXIT.USER_ERROR,
        );
        return;
      }
      const result = await revokeRotation(c.rotation, {
        force: opts.forceRevoke,
        agentMode: isAgentMode(),
        reason: globalOpts.reason,
        auditLog: globalOpts.auditLog,
      });
      if (!result.ok) {
        emit(
          makeEnvelope({
            command: "revoke",
            status: "error",
            startedAt: started,
            agentMode: isAgentMode(),
            errors: result.errors,
          }),
          EXIT.USER_ERROR,
        );
        return;
      }
      saveCheckpoint({ ...c, rotation: c.rotation, savedAt: new Date().toISOString() });
      archiveToHistory(c.rotation);
      emit(
        makeEnvelope({
          command: "revoke",
          status: "success",
          startedAt: started,
          agentMode: isAgentMode(),
          data: { rotation_id: rotationId, revoked: true },
          next_actions: ["Rotation closed"],
        }),
        EXIT.OK,
      );
    });

  program
    .command("incident")
    .argument("<file>", "incident YAML file")
    .option("--max-rotations <n>", "hard cap", (v) => Number.parseInt(v, 10))
    .option("--dry-run", "print the plan without rotating anything")
    .action(async (file: string, opts: { maxRotations?: number; dryRun?: boolean }) => {
      const started = Date.now();
      const globalOpts = program.opts();
      if (!opts.dryRun) {
        enforceAgentMode({
          command: "incident",
          reason: globalOpts.reason,
          yes: globalOpts.yes,
          auditLog: globalOpts.auditLog,
          maxRotations: opts.maxRotations,
        });
      }
      const config = loadConfig(globalOpts.config);
      const incident = loadIncident(file);
      const selected = selectByIncident(config, incident);
      assertMaxRotations(selected.length, opts.maxRotations);
      process.stderr.write(`Incident ${incident.id}: ${selected.length} secret(s) match scope.\n`);
      if (opts.dryRun) {
        emit(
          makeEnvelope({
            command: "incident",
            status: "success",
            startedAt: started,
            agentMode: isAgentMode(),
            data: {
              incident_id: incident.id,
              dry_run: true,
              affected: selected.length,
              rotations: selected.map((s) => ({
                secret_id: s.id,
                adapter: s.adapter,
                consumers: s.consumers.map((c) => `${c.type}/${c.params.var_name}`),
              })),
            },
            next_actions: selected.length
              ? [`Run \`rotate incident ${file} --yes --reason "..."\` to execute`]
              : ["No secrets matched the incident scope — check tags in rotate.config.yaml"],
          }),
          EXIT.OK,
        );
        return;
      }
      const results = [];
      for (const secret of selected) {
        const r = await applyRotation(secret, {
          reason: globalOpts.reason ?? `incident:${incident.id}`,
          agentMode: isAgentMode(),
          auditLog: globalOpts.auditLog,
        });
        results.push(r);
      }
      const anyError = results.some((r) => r.envelopeStatus === "error");
      emit(
        makeEnvelope({
          command: "incident",
          status: anyError ? "partial" : "success",
          startedAt: started,
          agentMode: isAgentMode(),
          data: {
            incident_id: incident.id,
            affected: selected.length,
            rotations: results.map((r) => ({
              rotation_id: r.rotation.id,
              secret_id: r.rotation.secretId,
              status: r.rotation.status,
            })),
          },
          next_actions: results
            .filter((r) => r.rotation.status === "in_grace")
            .map((r) => `Check \`rotate status ${r.rotation.id}\` then revoke when consumers sync`),
        }),
        anyError ? EXIT.PROVIDER_ERROR : EXIT.OK,
      );
    });

  try {
    await program.parseAsync(argv);
  } catch (err) {
    if (err instanceof RotateError) {
      const started = Date.now();
      emit(
        makeEnvelope({
          command: "unknown",
          status: "error",
          startedAt: started,
          agentMode: isAgentMode(),
          errors: [err.adapterError],
        }),
        err.exitCode,
      );
      return;
    }
    throw err;
  }
}

export function exit(code: number): never {
  process.exit(code);
}

// Convenience helper for audit-log append from tests.
export { appendAudit };
