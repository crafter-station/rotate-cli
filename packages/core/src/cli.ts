import { Command } from "commander";
import { assertMaxRotations, enforceAgentMode, isAgentMode } from "./agent-mode.ts";
import { runAuthLoginFlow } from "./auth-flow.ts";
import { renderAuthList, renderAuthLoginSuccess, renderAuthLogoutResult } from "./auth-render.ts";
import {
  buildAuthSummary,
  getAuthDefinition,
  listAuthDefinitions,
  listAuthEntries,
  logoutRegisteredAuth,
} from "./auth.ts";
import {
  appendAudit,
  archiveToHistory,
  ensureStateDirs,
  listCheckpoints,
  loadCheckpoint,
  saveCheckpoint,
} from "./checkpoints.ts";
import { loadConfig, loadIncident, selectByIncident, selectByQuery } from "./config.ts";
import { resolveCurrentValue } from "./current-value.ts";
import { emit, makeEnvelope } from "./envelope.ts";
import { EXIT, RotateError } from "./errors.ts";
import { applyRotation, preloadOwnershipForSecrets, revokeRotation } from "./orchestrator.ts";
import { createPromptIO } from "./prompt.ts";
import { getAdapter, listAdapters, listConsumers } from "./registry.ts";
import type { PromptChoice, PromptIO } from "./types.ts";

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

  const authCommand = program.command("auth").description("manage provider auth");

  authCommand
    .command("list")
    .description("list auth providers and local auth state")
    .action(async () => {
      const started = Date.now();
      const entries = await listAuthEntries();
      if (shouldRenderPretty(program)) {
        renderAuthList(entries);
        process.exit(EXIT.OK);
      }
      emit(
        makeEnvelope({
          command: "auth:list",
          status: "success",
          startedAt: started,
          agentMode: isAgentMode(),
          data: { entries },
          next_actions: entries
            .filter((entry) => entry.status === "missing")
            .map(
              (entry) =>
                `Run \`rotate auth login ${entry.name}\` to configure ${entry.displayName}`,
            ),
        }),
        EXIT.OK,
      );
    });

  authCommand
    .command("login")
    .argument("[provider]")
    .description("set up provider auth")
    .action(async (provider?: string) => {
      const started = Date.now();
      const io = createPromptIO();
      try {
        if (!io.isInteractive) {
          throw new RotateError(
            {
              code: "unsupported",
              message: "rotate auth login requires an interactive terminal",
              provider: "rotate-cli",
              retryable: false,
            },
            EXIT.USER_ERROR,
          );
        }
        const selectedProvider = provider ?? (await promptForAuthProvider(io));
        const definition = getAuthDefinition(selectedProvider);
        if (!definition) {
          throw new RotateError(
            {
              code: "invalid_spec",
              message: `unknown auth provider: ${selectedProvider}`,
              provider: "rotate-cli",
              retryable: false,
            },
            EXIT.USER_ERROR,
          );
        }
        const ctx = await runAuthLoginFlow(definition, io);
        const summary = buildAuthSummary(selectedProvider);
        if (shouldRenderPretty(program)) {
          renderAuthLoginSuccess({
            displayName: summary.displayName,
            source: ctx.kind === "env" ? "env" : "stored",
            envVars: summary.envVars,
            setupUrl: summary.setupUrl,
          });
          process.exit(EXIT.OK);
        }
        emit(
          makeEnvelope({
            command: "auth:login",
            status: "success",
            startedAt: started,
            agentMode: isAgentMode(),
            data: {
              provider: summary.name,
              display_name: summary.displayName,
              source: ctx.kind === "env" ? "env" : "stored",
              env_vars: summary.envVars,
              setup_url: summary.setupUrl,
            },
            next_actions: [
              `Run \`rotate auth list\` to confirm ${summary.displayName} is configured`,
              "Run `rotate doctor` to verify registered adapters and consumers",
            ],
          }),
          EXIT.OK,
        );
      } finally {
        await io.close();
      }
    });

  authCommand
    .command("logout")
    .argument("<provider>")
    .description("remove rotate-managed provider auth")
    .action(async (provider: string) => {
      const started = Date.now();
      const definition = getAuthDefinition(provider);
      if (!definition) {
        emit(
          makeEnvelope({
            command: "auth:logout",
            status: "error",
            startedAt: started,
            agentMode: isAgentMode(),
            errors: [
              {
                code: "invalid_spec",
                message: `unknown auth provider: ${provider}`,
                provider: "rotate-cli",
                retryable: false,
              },
            ],
          }),
          EXIT.USER_ERROR,
        );
        return;
      }
      const removed = await logoutRegisteredAuth(provider);
      const envStillConfigured = definition.envVars.some((name) => Boolean(process.env[name]));
      if (shouldRenderPretty(program)) {
        renderAuthLogoutResult({
          displayName: definition.displayName,
          removed,
          envStillConfigured,
          envVars: definition.envVars,
        });
        process.exit(EXIT.OK);
      }
      emit(
        makeEnvelope({
          command: "auth:logout",
          status: "success",
          startedAt: started,
          agentMode: isAgentMode(),
          data: {
            provider,
            removed,
            env_still_configured: envStillConfigured,
          },
          next_actions: envStillConfigured
            ? [
                `${definition.displayName} still resolves from ${definition.envVars.join(", ")}`,
                `Unset ${definition.envVars.join(" or ")} if you want auth to be fully unavailable`,
              ]
            : [
                `Run \`rotate auth list\` to confirm ${definition.displayName} is no longer configured`,
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
    .option("--skip-unknown", "skip secrets where ownership cannot be determined")
    .option(
      "--force-rotate-other",
      "rotate even when the secret belongs to another account (changes billing)",
    )
    .option("--no-ownership-check", "disable the ownership gate entirely (forbidden in agent mode)")
    .action(
      async (
        idsArg: string[] | undefined,
        opts: {
          provider?: string;
          tag?: string;
          maxRotations?: number;
          parallel: number;
          verify: boolean;
          skipUnknown?: boolean;
          forceRotateOther?: boolean;
          ownershipCheck?: boolean;
        },
      ) => {
        const ids = idsArg ?? [];
        const started = Date.now();
        const globalOpts = program.opts();
        const noOwnershipCheck = opts.ownershipCheck === false;
        enforceAgentMode({
          command: "apply",
          reason: globalOpts.reason,
          yes: globalOpts.yes,
          maxRotations: opts.maxRotations,
          auditLog: globalOpts.auditLog,
          skipVerify: opts.verify === false,
          noOwnershipCheck,
          forceRotateOther: opts.forceRotateOther,
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
        const { map: preloadMap } = noOwnershipCheck
          ? { map: new Map() }
          : await preloadOwnershipForSecrets(selected);
        const results = [];
        for (const secret of selected) {
          const { value: currentValue } = noOwnershipCheck
            ? { value: null }
            : await resolveCurrentValue(secret);
          const r = await applyRotation(secret, {
            reason: globalOpts.reason,
            agentMode: isAgentMode(),
            auditLog: globalOpts.auditLog,
            parallel: opts.parallel,
            skipVerify: opts.verify === false,
            currentValue: currentValue ?? undefined,
            ownershipPreload: preloadMap.get(secret.adapter),
            skipUnknown: opts.skipUnknown,
            forceRotateOther: opts.forceRotateOther,
            noOwnershipCheck,
          });
          results.push(r);
        }
        const anyError = results.some((r) => r.envelopeStatus === "error");
        const anyPartial = results.some((r) => r.envelopeStatus === "partial");
        const anySkipped = results.some((r) => r.envelopeStatus === "skipped");
        const allSkipped =
          results.length > 0 && results.every((r) => r.envelopeStatus === "skipped");
        const status = anyError
          ? "error"
          : allSkipped
            ? "partial"
            : anyPartial || anySkipped
              ? "partial"
              : "success";
        const nextActions = results
          .filter((r) => r.rotation.status === "in_grace")
          .map(
            (r) =>
              `Run \`rotate status ${r.rotation.id} --json\` to check sync; \`rotate revoke ${r.rotation.id}\` when ready`,
          );
        const skippedResults = results.filter((r) => r.envelopeStatus === "skipped");
        const skipped = skippedResults.map((r) => ({
          secret_id: r.rotation.secretId,
          adapter: r.rotation.adapter,
          reason: r.rotation.skipReason?.kind,
          evidence: r.rotation.skipReason?.evidence,
          verdict: r.rotation.ownership?.verdict,
          strategy: r.rotation.ownership?.strategy,
        }));
        const ownershipSummary = buildOwnershipSummary(results);
        const skipActions = buildSkipActions(skippedResults);
        emit(
          makeEnvelope({
            command: "apply",
            status,
            startedAt: started,
            agentMode: isAgentMode(),
            data: {
              rotations: results
                .filter((r) => r.envelopeStatus !== "skipped")
                .map((r) => ({
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
              skipped,
              ownership_summary: ownershipSummary,
            },
            next_actions: [...nextActions, ...skipActions],
          }),
          anyError ? EXIT.PROVIDER_ERROR : anyPartial ? EXIT.IN_GRACE_WARNING : EXIT.OK,
        );
      },
    );

  program
    .command("preview-ownership")
    .description("check which secrets you own without rotating anything")
    .argument("[selector...]", "secret identifiers (optional with --provider/--tag)")
    .option("--provider <name>")
    .option("--tag <name>")
    .action(async (idsArg: string[] | undefined, opts: { provider?: string; tag?: string }) => {
      const ids = idsArg ?? [];
      const started = Date.now();
      const globalOpts = program.opts();
      const config = loadConfig(globalOpts.config);
      const selected = selectByQuery(config, { ids, provider: opts.provider, tag: opts.tag });
      if (!selected.length) {
        emit(
          makeEnvelope({
            command: "preview-ownership",
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
      const { map: preloadMap, errors: preloadErrors } = await preloadOwnershipForSecrets(selected);
      const checks = await Promise.all(
        selected.map(async (secret) => {
          const adapter = getAdapter(secret.adapter);
          if (!adapter?.ownedBy) {
            return {
              secret_id: secret.id,
              adapter: secret.adapter,
              verdict: null,
              reason: "adapter has no ownedBy() method",
            };
          }
          const {
            value: currentValue,
            source,
            error: resolveError,
          } = await resolveCurrentValue(secret);
          if (!currentValue) {
            return {
              secret_id: secret.id,
              adapter: secret.adapter,
              verdict: "unknown" as const,
              reason:
                resolveError ??
                (source === "unavailable"
                  ? "current value unavailable (set currentValueEnv or use vercel-env consumer)"
                  : "current value empty"),
            };
          }
          try {
            const ctx = await adapter.auth();
            const ownership = await adapter.ownedBy(currentValue, ctx, {
              preload: preloadMap.get(secret.adapter),
            });
            return {
              secret_id: secret.id,
              adapter: secret.adapter,
              verdict: ownership.verdict,
              admin_can_bill: ownership.adminCanBill,
              scope: ownership.scope,
              confidence: ownership.confidence,
              strategy: ownership.strategy,
              evidence: ownership.evidence,
            };
          } catch (cause) {
            return {
              secret_id: secret.id,
              adapter: secret.adapter,
              verdict: "unknown" as const,
              reason: String(cause),
            };
          }
        }),
      );

      const summary = checks.reduce(
        (acc, c) => {
          if (c.verdict === "self") acc.self++;
          else if (c.verdict === "other") acc.other++;
          else if (c.verdict === "unknown") acc.unknown++;
          else acc.not_checked++;
          return acc;
        },
        { self: 0, other: 0, unknown: 0, not_checked: 0 },
      );

      const nextActions = [];
      if (summary.self > 0) {
        nextActions.push(
          `${summary.self} secret(s) ready to rotate — run \`rotate apply\` with matching selector`,
        );
      }
      if (summary.other > 0) {
        nextActions.push(
          `${summary.other} secret(s) belong to another account — coordinate with the owner or use --force-rotate-other`,
        );
      }
      if (summary.unknown > 0) {
        nextActions.push(
          `${summary.unknown} secret(s) have unknown ownership — add currentValueEnv hints to rotate.config.yaml`,
        );
      }
      if (preloadErrors.size > 0) {
        nextActions.push(
          `preload failed for: ${[...preloadErrors.keys()].join(", ")} — check auth with \`rotate doctor\``,
        );
      }

      emit(
        makeEnvelope({
          command: "preview-ownership",
          status: "success",
          startedAt: started,
          agentMode: isAgentMode(),
          data: {
            total: checks.length,
            checks,
            summary,
            preload_errors: Object.fromEntries(preloadErrors),
          },
          next_actions: nextActions,
        }),
        EXIT.OK,
      );
    });

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
    .option("--skip-unknown", "skip secrets where ownership cannot be determined")
    .option(
      "--force-rotate-other",
      "rotate even when a secret belongs to another account (changes billing)",
    )
    .option("--no-ownership-check", "disable the ownership gate entirely")
    .action(
      async (
        file: string,
        opts: {
          maxRotations?: number;
          dryRun?: boolean;
          skipUnknown?: boolean;
          forceRotateOther?: boolean;
          ownershipCheck?: boolean;
        },
      ) => {
        const started = Date.now();
        const globalOpts = program.opts();
        const noOwnershipCheck = opts.ownershipCheck === false;
        if (!opts.dryRun) {
          enforceAgentMode({
            command: "incident",
            reason: globalOpts.reason,
            yes: globalOpts.yes,
            auditLog: globalOpts.auditLog,
            maxRotations: opts.maxRotations,
            noOwnershipCheck,
            forceRotateOther: opts.forceRotateOther,
          });
        }
        const config = loadConfig(globalOpts.config);
        const incident = loadIncident(file);
        const selected = selectByIncident(config, incident);
        assertMaxRotations(selected.length, opts.maxRotations);
        process.stderr.write(
          `Incident ${incident.id}: ${selected.length} secret(s) match scope.\n`,
        );
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
        const { map: preloadMap } = noOwnershipCheck
          ? { map: new Map() }
          : await preloadOwnershipForSecrets(selected);
        const results = [];
        for (const secret of selected) {
          const { value: currentValue } = noOwnershipCheck
            ? { value: null }
            : await resolveCurrentValue(secret);
          const r = await applyRotation(secret, {
            reason: globalOpts.reason ?? `incident:${incident.id}`,
            agentMode: isAgentMode(),
            auditLog: globalOpts.auditLog,
            currentValue: currentValue ?? undefined,
            ownershipPreload: preloadMap.get(secret.adapter),
            skipUnknown: opts.skipUnknown,
            forceRotateOther: opts.forceRotateOther,
            noOwnershipCheck,
          });
          results.push(r);
        }
        const anyError = results.some((r) => r.envelopeStatus === "error");
        const skippedResults = results.filter((r) => r.envelopeStatus === "skipped");
        const skipped = skippedResults.map((r) => ({
          secret_id: r.rotation.secretId,
          adapter: r.rotation.adapter,
          reason: r.rotation.skipReason?.kind,
          evidence: r.rotation.skipReason?.evidence,
          verdict: r.rotation.ownership?.verdict,
          strategy: r.rotation.ownership?.strategy,
        }));
        const ownershipSummary = buildOwnershipSummary(results);
        const skipActions = buildSkipActions(skippedResults);
        emit(
          makeEnvelope({
            command: "incident",
            status: anyError ? "partial" : "success",
            startedAt: started,
            agentMode: isAgentMode(),
            data: {
              incident_id: incident.id,
              affected: selected.length,
              rotations: results
                .filter((r) => r.envelopeStatus !== "skipped")
                .map((r) => ({
                  rotation_id: r.rotation.id,
                  secret_id: r.rotation.secretId,
                  status: r.rotation.status,
                })),
              skipped,
              ownership_summary: ownershipSummary,
            },
            next_actions: [
              ...results
                .filter((r) => r.rotation.status === "in_grace")
                .map(
                  (r) => `Check \`rotate status ${r.rotation.id}\` then revoke when consumers sync`,
                ),
              ...skipActions,
            ],
          }),
          anyError ? EXIT.PROVIDER_ERROR : EXIT.OK,
        );
      },
    );

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

async function promptForAuthProvider(io: PromptIO): Promise<string> {
  const definitions = listAuthDefinitions();
  if (!definitions.length) {
    throw new RotateError(
      {
        code: "unsupported",
        message: "no auth providers are registered",
        provider: "rotate-cli",
        retryable: false,
      },
      EXIT.USER_ERROR,
    );
  }
  const choices: PromptChoice[] = definitions.map((definition) => ({
    label: definition.displayName,
    value: definition.name,
    hint: definition.notes?.[0],
  }));
  return io.select("Select provider", choices);
}

function shouldRenderPretty(program: Command): boolean {
  const opts = program.opts<{ json?: boolean; pretty?: boolean }>();
  if (opts.json) return false;
  if (opts.pretty) return true;
  return true;
}

// Convenience helper for audit-log append from tests.
export { appendAudit };

function buildOwnershipSummary(results: Array<{ rotation: { ownership?: { verdict: string } } }>): {
  self: number;
  other: number;
  unknown: number;
  not_checked: number;
} {
  const summary = { self: 0, other: 0, unknown: 0, not_checked: 0 };
  for (const r of results) {
    const v = r.rotation.ownership?.verdict;
    if (v === "self") summary.self++;
    else if (v === "other") summary.other++;
    else if (v === "unknown") summary.unknown++;
    else summary.not_checked++;
  }
  return summary;
}

function buildSkipActions(
  skipped: Array<{
    rotation: { secretId: string; adapter: string; skipReason?: { kind: string } };
  }>,
): string[] {
  if (!skipped.length) return [];
  const actions: string[] = [];
  const byKind = new Map<string, string[]>();
  for (const r of skipped) {
    const kind = r.rotation.skipReason?.kind ?? "unknown";
    if (!byKind.has(kind)) byKind.set(kind, []);
    byKind.get(kind)?.push(r.rotation.secretId);
  }
  for (const [kind, ids] of byKind.entries()) {
    if (kind === "ownership-other") {
      actions.push(
        `${ids.length} secret(s) belong to another account: ${ids.join(", ")} — ask the owner to run \`rotate apply\` with their config, or use --force-rotate-other to bypass (changes billing)`,
      );
    } else if (kind === "ownership-self-member-only") {
      actions.push(
        `${ids.length} secret(s) in your org but you lack admin: ${ids.join(", ")} — ask an admin to rotate`,
      );
    } else if (kind === "ownership-unknown-skipped") {
      actions.push(
        `${ids.length} secret(s) with unknown ownership: ${ids.join(", ")} — re-run without --skip-unknown or add currentValueEnv hints`,
      );
    } else if (kind === "ownership-current-value-unavailable") {
      actions.push(
        `${ids.length} secret(s) with unavailable current value: ${ids.join(", ")} — set currentValueEnv in rotate.config.yaml or use --no-ownership-check`,
      );
    } else {
      actions.push(`${ids.length} secret(s) skipped (${kind}): ${ids.join(", ")}`);
    }
  }
  return actions;
}
