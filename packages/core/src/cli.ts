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
import { hashSecretValue, resolveCurrentValue } from "./current-value.ts";
import { emit, makeEnvelope } from "./envelope.ts";
import { EXIT, RotateError } from "./errors.ts";
import { applyRotation, preloadOwnershipForSecrets, revokeRotation } from "./orchestrator.ts";
import { createPromptIO } from "./prompt.ts";
import { getAdapter, listAdapters, listConsumers } from "./registry.ts";
import {
  createApplyProgressRenderer,
  createOwnershipProgressRenderer,
  createScanProgressRenderer,
  renderApply,
  renderDoctor,
  renderPlan,
  renderPreviewOwnership,
  renderRevoke,
  renderScanSummary,
  shouldRenderPretty as renderShouldPretty,
  renderStatusList,
} from "./render.ts";
import {
  DEFAULT_SCAN_MAX_AGE,
  parseDurationMs,
  readScanCache,
  scanCacheAgeMs,
  scanCachePath,
  writeScanCache,
} from "./scan-cache.ts";
import { fetchProjectSiblings, resolveVercelTokenForScan, scanVercel } from "./scan.ts";
import type { PromptChoice, PromptIO } from "./types.ts";

export async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program
    .name("rotate-cli")
    .description("Agent-first secrets rotation CLI. Local-first, zero servers.")
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
    .command("scan")
    .description(
      "discover every env var across all your Vercel projects + map to rotate-cli adapters",
    )
    .option("--team <slug>", "scan only this team")
    .option("--include-public", "include NEXT_PUBLIC_* vars (default: skip)")
    .action(async (opts: { team?: string; includePublic?: boolean }) => {
      const started = Date.now();
      const token = resolveVercelTokenForScan();
      if (!token) {
        emit(
          makeEnvelope({
            command: "scan",
            status: "error",
            startedAt: started,
            agentMode: isAgentMode(),
            errors: [
              {
                code: "auth_failed",
                message:
                  "VERCEL_TOKEN missing. Create one at https://vercel.com/account/tokens (scope: All teams) and add to .env.local",
                provider: "rotate-cli",
                retryable: false,
              },
            ],
          }),
          EXIT.USER_ERROR,
        );
        return;
      }
      const pretty = shouldRenderPretty(program);
      const progress = pretty ? createScanProgressRenderer() : null;
      let result: Awaited<ReturnType<typeof scanVercel>>;
      try {
        result = await scanVercel({
          token,
          teamSlug: opts.team,
          includePublic: opts.includePublic,
          onProgress: progress?.handle,
        });
      } catch (cause) {
        progress?.stop();
        emit(
          makeEnvelope({
            command: "scan",
            status: "error",
            startedAt: started,
            agentMode: isAgentMode(),
            errors: [
              {
                code: "provider_error",
                message: String(cause),
                provider: "vercel",
                retryable: true,
              },
            ],
          }),
          EXIT.PROVIDER_ERROR,
        );
        return;
      }
      progress?.stop();
      const byAdapter: Record<string, number> = {};
      for (const s of result.secrets) {
        byAdapter[s.adapter] = (byAdapter[s.adapter] ?? 0) + 1;
      }
      // Persist to disk so who/apply --from-scan can reuse without re-hitting Vercel.
      writeScanCache({
        version: 1,
        generatedAt: new Date().toISOString(),
        teamsScanned: result.teamsScanned,
        projectsScanned: result.projectsScanned,
        totalSecrets: result.secrets.length,
        totalSkipped: result.skipped.length,
        byAdapter,
        secrets: result.secrets,
        skipped: result.skipped,
      });
      if (pretty) {
        renderScanSummary({
          projectsScanned: result.projectsScanned,
          teamsScanned: result.teamsScanned.length,
          totalSecrets: result.secrets.length,
          totalSkipped: result.skipped.length,
          byAdapter,
        });
        process.exit(EXIT.OK);
      }
      emit(
        makeEnvelope({
          command: "scan",
          status: "success",
          startedAt: started,
          agentMode: isAgentMode(),
          data: {
            teams_scanned: result.teamsScanned,
            projects_scanned: result.projectsScanned,
            total_secrets: result.secrets.length,
            total_skipped: result.skipped.length,
            by_adapter: byAdapter,
            secrets: result.secrets,
            skipped: result.skipped,
          },
          next_actions: [
            "rotate-cli who --from-scan  # ownership check every mapped secret",
            'rotate-cli apply --from-scan --tag non-sensitive --yes --reason "..."',
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
      const rows: Array<{
        kind: string;
        name: string;
        ok: boolean;
        mode?: "auto" | "manual-assist" | "no-check";
        authStatus: "ok" | "missing" | "not-required";
        error?: string;
      }> = [];
      for (const adapter of listAdapters()) {
        const mode: "auto" | "manual-assist" | "no-check" = adapter.mode ?? "auto";
        try {
          await adapter.auth();
          rows.push({
            kind: "adapter",
            name: adapter.name,
            ok: true,
            mode,
            authStatus: "ok",
          });
        } catch (err) {
          // Manual-assist adapters do not require pre-configured auth because
          // the user pastes a fresh secret during each apply. no-check adapters
          // never auth against a provider. Both cases are informational, not
          // blocking, so they do not count toward the non-zero exit.
          const bypass = mode === "manual-assist" || mode === "no-check";
          rows.push({
            kind: "adapter",
            name: adapter.name,
            ok: bypass,
            mode,
            authStatus: bypass ? "not-required" : "missing",
            error: bypass ? undefined : String(err),
          });
        }
      }
      for (const consumer of listConsumers()) {
        try {
          await consumer.auth();
          rows.push({
            kind: "consumer",
            name: consumer.name,
            ok: true,
            authStatus: "ok",
          });
        } catch (err) {
          rows.push({
            kind: "consumer",
            name: consumer.name,
            ok: false,
            authStatus: "missing",
            error: String(err),
          });
        }
      }
      const failing = rows.filter((r) => !r.ok);
      if (shouldRenderPretty(program)) {
        renderDoctor(rows);
        process.exit(failing.length ? EXIT.PROVIDER_ERROR : EXIT.OK);
      }
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
    .description("dry-run: print the rotation plan without mutating anything")
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
      const planItems = selected.map((s) => ({
        id: s.id,
        adapter: s.adapter,
        consumer_count: s.consumers.length,
        consumers: s.consumers,
      }));
      if (shouldRenderPretty(program)) {
        renderPlan(planItems);
        process.exit(selected.length ? EXIT.OK : EXIT.USER_ERROR);
      }
      emit(
        makeEnvelope({
          command: "plan",
          status: "success",
          startedAt: started,
          agentMode: isAgentMode(),
          data: { selected: planItems },
          next_actions: selected.length
            ? [`Run \`rotate apply ${(ids ?? []).join(" ")} --yes --reason "..."\` to execute`]
            : ["Selector matched no secrets — check rotate.config.yaml"],
        }),
        selected.length ? EXIT.OK : EXIT.USER_ERROR,
      );
    });

  program
    .command("apply")
    .description("rotate secrets: create new, propagate to consumers, verify, enter grace")
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
    .option(
      "--no-from-scan",
      "load selector targets from rotate.config.yaml instead of the scan cache",
    )
    .option(
      "--scan-max-age <duration>",
      `max age of cached scan before forcing a refresh (default: ${DEFAULT_SCAN_MAX_AGE})`,
      DEFAULT_SCAN_MAX_AGE,
    )
    .option("--fresh", "ignore the cached scan and force a fresh scan")
    .option(
      "--confirm-bulk",
      "required when scan-cache source selects more than 20 rotations (safety guard)",
    )
    .option(
      "--auto-only",
      "rotate only auto-mode adapters; list manual-assist adapters as pending (default)",
    )
    .option(
      "--manual-only",
      "rotate only manual-assist adapters; pauses for dashboard steps (requires TTY)",
    )
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
          fromScan?: boolean;
          scanMaxAge?: string;
          fresh?: boolean;
          confirmBulk?: boolean;
          autoOnly?: boolean;
          manualOnly?: boolean;
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
        if (opts.autoOnly && opts.manualOnly) {
          emit(
            makeEnvelope({
              command: "apply",
              status: "error",
              startedAt: started,
              agentMode: isAgentMode(),
              errors: [
                {
                  code: "invalid_spec",
                  message: "--auto-only and --manual-only are mutually exclusive",
                  provider: "rotate-cli",
                  retryable: false,
                },
              ],
            }),
            EXIT.USER_ERROR,
          );
          return;
        }
        // Default mode policy: agent-mode always = auto-only (never prompt).
        // Interactive default = auto-only too (safe unattended run) unless
        // the user explicitly asks for --manual-only.
        const manualOnly = Boolean(opts.manualOnly);
        const autoOnly = manualOnly ? false : Boolean(opts.autoOnly) || !opts.manualOnly;
        const allSelected = opts.fromScan
          ? await loadFromScan({
              ids,
              provider: opts.provider,
              tag: opts.tag,
              fresh: Boolean(opts.fresh),
              maxAge: opts.scanMaxAge ?? DEFAULT_SCAN_MAX_AGE,
            })
          : (() => {
              const config = loadConfig(globalOpts.config);
              return selectByQuery(config, { ids, provider: opts.provider, tag: opts.tag });
            })();

        // Partition by adapter.mode. The apply loop only consumes entries
        // matching the chosen phase; the other set is reported as pending.
        const autoEntries: typeof allSelected = [];
        const manualEntries: typeof allSelected = [];
        for (const s of allSelected) {
          const adapter = getAdapter(s.adapter);
          const mode = adapter?.mode ?? "auto";
          if (mode === "manual-assist") manualEntries.push(s);
          else autoEntries.push(s);
        }
        const selected = manualOnly ? manualEntries : autoEntries;
        const deferred = manualOnly ? autoEntries : manualEntries;

        assertMaxRotations(selected.length, opts.maxRotations);
        if (opts.fromScan && selected.length > 20 && !opts.confirmBulk) {
          emit(
            makeEnvelope({
              command: "apply",
              status: "error",
              startedAt: started,
              agentMode: isAgentMode(),
              errors: [
                {
                  code: "invalid_spec",
                  message: `selector resolved to ${selected.length} rotations (bulk); pass --confirm-bulk to proceed`,
                  provider: "rotate-cli",
                  retryable: false,
                },
              ],
            }),
            EXIT.USER_ERROR,
          );
          return;
        }
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
        const applyPretty = shouldRenderPretty(program);
        const applyProgress = applyPretty ? createApplyProgressRenderer() : null;
        // Manual-assist adapters need a real interactive PromptIO. Auto-only
        // adapters get `undefined` — the orchestrator rejects misuse.
        const applyIO = manualOnly ? createPromptIO() : undefined;

        // Preload phase: announce to the renderer, fetch each adapter's
        // ownership index, then the Vercel sibling env vars. Mirrors the
        // two-phase UI the who command uses so the user sees progress
        // instead of a silent 15 second pause on large selections.
        const uniqueAdapters = [...new Set(selected.map((s) => s.adapter))];
        const adaptersWithPreload = uniqueAdapters.filter((n) => getAdapter(n)?.preloadOwnership);
        const preloadMap = new Map<string, import("./types.ts").OwnershipPreload>();
        if (!noOwnershipCheck && adaptersWithPreload.length > 0) {
          applyProgress?.handle({ kind: "preload-start", adapters: adaptersWithPreload });
          await Promise.all(
            adaptersWithPreload.map(async (name) => {
              const adapter = getAdapter(name);
              if (!adapter?.preloadOwnership) return;
              const startedPreload = Date.now();
              try {
                const ctx = await adapter.auth();
                const preload = await adapter.preloadOwnership(ctx);
                preloadMap.set(name, preload);
                applyProgress?.handle({
                  kind: "preload-done",
                  adapter: name,
                  durationMs: Date.now() - startedPreload,
                  info: summarizePreload(preload),
                });
              } catch (cause) {
                applyProgress?.handle({
                  kind: "preload-failed",
                  adapter: name,
                  durationMs: Date.now() - startedPreload,
                  error: String(cause),
                });
              }
            }),
          );
        }

        // Pre-fetch project siblings so resolveCurrentValue can read
        // coLocatedVars without N extra Vercel round-trips. Same pattern as
        // the who command. Only activates when we're consuming the scan
        // cache (--from-scan) AND have a Vercel token.
        const applyProjectVars = new Map<string, Record<string, string>>();
        if (opts.fromScan && !noOwnershipCheck) {
          const token = resolveVercelTokenForScan();
          if (token) {
            const projectEntries: Array<{ key: string; teamId?: string }> = [];
            const seenProjects = new Set<string>();
            for (const s of selected) {
              for (const c of s.consumers) {
                if (c.type === "vercel-env" && c.params.project) {
                  const k = `${c.params.team ?? ""}:${c.params.project}`;
                  if (!seenProjects.has(k)) {
                    seenProjects.add(k);
                    projectEntries.push({ key: c.params.project, teamId: c.params.team });
                  }
                }
              }
            }
            if (projectEntries.length > 0) {
              applyProgress?.handle({
                kind: "siblings-start",
                totalProjects: projectEntries.length,
              });
              const siblingStart = Date.now();
              const siblings = await fetchProjectSiblings({
                token,
                projects: projectEntries,
                onProgress: (p) => {
                  applyProgress?.handle({
                    kind: "siblings-progress",
                    completed: p.completed,
                    total: p.totalProjects,
                    decrypted: p.decrypted,
                    currentSlug: p.currentSlug,
                  });
                },
              });
              for (const [k, v] of siblings) applyProjectVars.set(k, v);
              applyProgress?.handle({
                kind: "siblings-done",
                decrypted: siblings.size,
                totalProjects: projectEntries.length,
                durationMs: Date.now() - siblingStart,
              });
            }
          }
        }

        // Resolve current value for each entry and group by (adapter, value_hash).
        // Each group rotates ONCE; the representative's consumers[] is the
        // union of every entry in the group, so propagate reaches every
        // Vercel project/env/repo that held the duplicated secret.
        type Group = {
          representative: (typeof selected)[number];
          members: Array<(typeof selected)[number]>;
          currentValue?: string;
          coLocatedVars?: Record<string, string>;
        };
        const groups = new Map<string, Group>();
        for (const secret of selected) {
          const projectKey = secret.consumers.find((c) => c.type === "vercel-env")?.params.project;
          const preFetchedVars = projectKey ? applyProjectVars.get(projectKey) : undefined;
          const { value: currentValue } = noOwnershipCheck
            ? { value: null }
            : await resolveCurrentValue(secret, { preFetchedVars });
          // Fallback when value can't be resolved: each such entry goes into
          // its own group keyed by secret.id, preserving 1-per-entry semantics.
          const key = currentValue
            ? `${secret.adapter}:${hashSecretValue(currentValue)}`
            : `unresolved:${secret.id}`;
          const existing = groups.get(key);
          if (existing) {
            existing.members.push(secret);
          } else {
            groups.set(key, {
              representative: secret,
              members: [secret],
              currentValue: currentValue ?? undefined,
              coLocatedVars: preFetchedVars,
            });
          }
        }

        const groupList = [...groups.values()];
        applyProgress?.handle({
          kind: "dedup",
          totalEntries: selected.length,
          uniqueGroups: groupList.length,
        });
        applyProgress?.handle({ kind: "start", total: groupList.length });
        const results = [];
        for (let i = 0; i < groupList.length; i++) {
          const group = groupList[i]!;
          const index = i + 1;
          const mergedConsumers = [
            ...new Map(
              group.members.flatMap((m) =>
                m.consumers.map((c) => [`${c.type}:${JSON.stringify(c.params)}`, c]),
              ),
            ).values(),
          ];
          const mergedSecret = {
            ...group.representative,
            consumers: mergedConsumers,
          };
          const label =
            group.members.length > 1
              ? `${group.representative.id} (+${group.members.length - 1} duplicate${group.members.length > 2 ? "s" : ""})`
              : group.representative.id;
          applyProgress?.handle({
            kind: "rotation-start",
            index,
            total: groupList.length,
            secretId: label,
            adapter: group.representative.adapter,
          });
          const rotationStarted = Date.now();
          const r = await applyRotation(mergedSecret, {
            reason: globalOpts.reason,
            agentMode: isAgentMode(),
            auditLog: globalOpts.auditLog,
            parallel: opts.parallel,
            skipVerify: opts.verify === false,
            currentValue: group.currentValue,
            ownershipPreload: preloadMap.get(group.representative.adapter),
            coLocatedVars: group.coLocatedVars,
            skipUnknown: opts.skipUnknown,
            forceRotateOther: opts.forceRotateOther,
            noOwnershipCheck,
            io: applyIO,
            onStep: (step) => applyProgress?.handle({ kind: "rotation-step", index, step }),
          });
          results.push(r);
          applyProgress?.handle({
            kind: "rotation-done",
            index,
            total: groupList.length,
            secretId: label,
            status: r.envelopeStatus,
            rotationId: r.rotation.id,
            durationMs: Date.now() - rotationStarted,
            note: r.rotation.skipReason?.kind ?? r.rotation.errors[0]?.message,
          });
        }
        applyProgress?.stop();
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
        await applyIO?.close();
        const nextActions = results
          .filter((r) => r.rotation.status === "in_grace")
          .map(
            (r) =>
              `Run \`rotate status ${r.rotation.id} --json\` to check sync; \`rotate revoke ${r.rotation.id}\` when ready`,
          );
        // Report entries deferred to the other phase so the user knows
        // what's still pending. e.g. after --auto-only finishes, tell them
        // to run --manual-only for the manual-assist adapters.
        if (deferred.length > 0) {
          const byAdapter = new Map<string, number>();
          for (const s of deferred) byAdapter.set(s.adapter, (byAdapter.get(s.adapter) ?? 0) + 1);
          const breakdown = [...byAdapter.entries()]
            .map(([a, n]) => `${a} (${n})`)
            .sort()
            .join(", ");
          const nextCmd = manualOnly
            ? "rotate-cli apply --from-scan --auto-only"
            : "rotate-cli apply --from-scan --manual-only";
          nextActions.push(
            `${deferred.length} rotation(s) deferred to the other phase: ${breakdown} — run \`${nextCmd}\` when ready`,
          );
        }
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
        const successfulRotations = results
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
          }));
        // Summary counts actual rotation outcomes. Gives the user a clear
        // tally of what actually happened during this apply run, independent
        // of the ownership gate breakdown (which the who command already
        // showed before they hit apply).
        const runSummary = {
          rotated: results.filter(
            (r) => r.envelopeStatus === "success" || r.envelopeStatus === "partial",
          ).length,
          skipped: results.filter((r) => r.envelopeStatus === "skipped").length,
          failed: results.filter((r) => r.envelopeStatus === "error").length,
          ownership: ownershipSummary,
        };
        if (applyPretty) {
          renderApply(successfulRotations, skipped, runSummary, [...nextActions, ...skipActions]);
          process.exit(
            anyError ? EXIT.PROVIDER_ERROR : anyPartial ? EXIT.IN_GRACE_WARNING : EXIT.OK,
          );
        }
        emit(
          makeEnvelope({
            command: "apply",
            status,
            startedAt: started,
            agentMode: isAgentMode(),
            data: {
              rotations: successfulRotations,
              skipped,
              summary: runSummary,
              ownership_summary: ownershipSummary,
              mode: manualOnly ? "manual-only" : "auto-only",
              deferred: deferred.map((s) => ({
                secret_id: s.id,
                adapter: s.adapter,
              })),
            },
            next_actions: [...nextActions, ...skipActions],
          }),
          anyError ? EXIT.PROVIDER_ERROR : anyPartial ? EXIT.IN_GRACE_WARNING : EXIT.OK,
        );
      },
    );

  program
    .command("preview-ownership")
    .alias("who")
    .description("check which secrets you own without rotating anything")
    .argument("[selector...]", "secret identifiers (optional with --provider/--tag)")
    .option("--provider <name>")
    .option("--tag <name>")
    .option(
      "--no-from-scan",
      "load selector targets from rotate.config.yaml instead of the scan cache",
    )
    .option(
      "--scan-max-age <duration>",
      `max age of cached scan before forcing a refresh (default: ${DEFAULT_SCAN_MAX_AGE})`,
      DEFAULT_SCAN_MAX_AGE,
    )
    .option("--fresh", "ignore the cached scan and force a fresh scan")
    .action(
      async (
        idsArg: string[] | undefined,
        opts: {
          provider?: string;
          tag?: string;
          fromScan?: boolean;
          scanMaxAge?: string;
          fresh?: boolean;
        },
      ) => {
        const ids = idsArg ?? [];
        const started = Date.now();
        const globalOpts = program.opts();
        const selected = opts.fromScan
          ? await loadFromScan({
              ids,
              provider: opts.provider,
              tag: opts.tag,
              fresh: Boolean(opts.fresh),
              maxAge: opts.scanMaxAge ?? DEFAULT_SCAN_MAX_AGE,
            })
          : (() => {
              const config = loadConfig(globalOpts.config);
              return selectByQuery(config, { ids, provider: opts.provider, tag: opts.tag });
            })();
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
                  message: opts.fromScan
                    ? "no scan cache found — run `rotate-cli scan` first"
                    : "selector matched no secrets",
                  provider: "rotate-cli",
                  retryable: false,
                },
              ],
            }),
            EXIT.USER_ERROR,
          );
          return;
        }
        const pretty = shouldRenderPretty(program);
        const progress = pretty ? createOwnershipProgressRenderer() : null;
        const uniqueAdapters = [...new Set(selected.map((s) => s.adapter))];
        progress?.handle({ kind: "preload-start", adapters: uniqueAdapters });

        const preloadMap = new Map<string, import("./types.ts").OwnershipPreload>();
        const preloadErrors = new Map<string, string>();
        await Promise.all(
          uniqueAdapters.map(async (name) => {
            const adapter = getAdapter(name);
            if (!adapter?.preloadOwnership) return;
            const startedPreload = Date.now();
            try {
              const ctx = await adapter.auth();
              const preload = await adapter.preloadOwnership(ctx);
              preloadMap.set(name, preload);
              progress?.handle({
                kind: "preload-done",
                adapter: name,
                durationMs: Date.now() - startedPreload,
                info: summarizePreload(preload),
              });
            } catch (cause) {
              preloadErrors.set(name, String(cause));
              progress?.handle({
                kind: "preload-failed",
                adapter: name,
                durationMs: Date.now() - startedPreload,
                error: String(cause),
              });
            }
          }),
        );

        // Fetch co-located env vars for projects whose adapters use
        // sibling-inheritance (clerk, supabase, turso, ...). This is what
        // makes "unknown" verdicts become "self"/"other" — without siblings
        // clerk literally cannot tell.
        const siblingAdapters = new Set(["clerk", "supabase", "turso", "polar", "upstash"]);
        const needsSiblings = selected.some((s) => siblingAdapters.has(s.adapter));
        let projectVars = new Map<string, Record<string, string>>();
        if (needsSiblings) {
          const token = resolveVercelTokenForScan();
          if (token) {
            const projectKeys = new Set<string>();
            const projectEntries: Array<{ key: string; teamId?: string }> = [];
            for (const secret of selected) {
              for (const c of secret.consumers) {
                if (c.type === "vercel-env" && c.params.project) {
                  const k = c.params.project;
                  const dedupKey = `${c.params.team ?? ""}:${k}`;
                  if (!projectKeys.has(dedupKey)) {
                    projectKeys.add(dedupKey);
                    projectEntries.push({ key: k, teamId: c.params.team });
                  }
                }
              }
            }
            progress?.handle({
              kind: "preload-done",
              adapter: "vercel-siblings",
              durationMs: 0,
              info: `fetching ${projectEntries.length} project(s)...`,
            });
            const siblingStart = Date.now();
            projectVars = await fetchProjectSiblings({ token, projects: projectEntries });
            progress?.handle({
              kind: "preload-done",
              adapter: "vercel-siblings",
              durationMs: Date.now() - siblingStart,
              info: `${projectVars.size}/${projectEntries.length} project(s) decrypted`,
            });
          } else {
            progress?.handle({
              kind: "preload-failed",
              adapter: "vercel-siblings",
              durationMs: 0,
              error: "VERCEL_TOKEN missing — siblings unavailable",
            });
          }
        }

        progress?.handle({ kind: "check-start", total: selected.length });
        const counters = { self: 0, other: 0, unknown: 0, notChecked: 0 };
        let done = 0;
        const concurrency = 10;
        const queue = [...selected.entries()];
        const checks: Array<{
          secret_id: string;
          adapter: string;
          verdict: "self" | "other" | "unknown" | null;
          admin_can_bill?: boolean;
          scope?: string;
          confidence?: string;
          strategy?: string;
          evidence?: string;
          reason?: string;
          /** sha256 prefix of the underlying value — used to dedup entries
           *  that point to the same secret across projects/envs. Omitted
           *  when the value couldn't be resolved. */
          value_hash?: string;
        }> = new Array(selected.length);
        async function worker(): Promise<void> {
          while (queue.length > 0) {
            const entry = queue.shift();
            if (!entry) break;
            const [idx, secret] = entry;
            const adapter = getAdapter(secret.adapter);
            let check: (typeof checks)[number];
            if (!adapter?.ownedBy) {
              check = {
                secret_id: secret.id,
                adapter: secret.adapter,
                verdict: null,
                reason: "adapter has no ownedBy() method",
              };
              counters.notChecked++;
            } else {
              const projectKey = secret.consumers.find((c) => c.type === "vercel-env")?.params
                .project;
              const preFetchedVars = projectKey ? projectVars.get(projectKey) : undefined;
              const {
                value: currentValue,
                source,
                error: resolveError,
              } = await resolveCurrentValue(secret, { preFetchedVars });
              if (!currentValue) {
                check = {
                  secret_id: secret.id,
                  adapter: secret.adapter,
                  verdict: "unknown",
                  reason:
                    resolveError ??
                    (source === "unavailable"
                      ? "current value unavailable (set currentValueEnv or use vercel-env consumer)"
                      : "current value empty"),
                };
                counters.unknown++;
              } else {
                try {
                  const ctx = await adapter.auth();
                  const ownership = await adapter.ownedBy(currentValue, ctx, {
                    preload: preloadMap.get(secret.adapter),
                    coLocatedVars: preFetchedVars,
                  });
                  check = {
                    secret_id: secret.id,
                    adapter: secret.adapter,
                    verdict: ownership.verdict,
                    admin_can_bill: ownership.adminCanBill,
                    scope: ownership.scope,
                    confidence: ownership.confidence,
                    strategy: ownership.strategy,
                    evidence: ownership.evidence,
                    value_hash: hashSecretValue(currentValue),
                  };
                  if (ownership.verdict === "self") counters.self++;
                  else if (ownership.verdict === "other") counters.other++;
                  else counters.unknown++;
                } catch (cause) {
                  check = {
                    secret_id: secret.id,
                    adapter: secret.adapter,
                    verdict: "unknown",
                    reason: String(cause),
                  };
                  counters.unknown++;
                }
              }
            }
            checks[idx] = check;
            done++;
            progress?.handle({
              kind: "check-progress",
              done,
              total: selected.length,
              self: counters.self,
              other: counters.other,
              unknown: counters.unknown,
              notChecked: counters.notChecked,
            });
          }
        }
        await Promise.all(
          Array.from({ length: Math.min(concurrency, selected.length) }, () => worker()),
        );
        progress?.stop();

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

        // Count unique underlying values per verdict. Two Vercel entries
        // holding the same secret hash to the same key, so summary.self=77
        // but only ~57 actual rotations to perform. This metric tells the
        // user what rotate-cli apply will actually do.
        const uniqueHashesByVerdict = { self: new Set<string>(), other: new Set<string>() };
        for (const c of checks) {
          if (!c.value_hash) continue;
          if (c.verdict === "self") uniqueHashesByVerdict.self.add(`${c.adapter}:${c.value_hash}`);
          else if (c.verdict === "other")
            uniqueHashesByVerdict.other.add(`${c.adapter}:${c.value_hash}`);
        }
        const uniqueCounts = {
          self: uniqueHashesByVerdict.self.size,
          other: uniqueHashesByVerdict.other.size,
        };

        const nextActions = [];
        if (summary.self > 0) {
          const rotationsNote =
            uniqueCounts.self > 0 && uniqueCounts.self < summary.self
              ? ` (${uniqueCounts.self} unique key${uniqueCounts.self === 1 ? "" : "s"} — rotate-cli apply deduplicates automatically)`
              : "";
          nextActions.push(
            `${summary.self} secret(s) ready to rotate${rotationsNote} — run \`rotate apply\` with matching selector`,
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

        const preloadErrorsObj = Object.fromEntries(preloadErrors);
        if (pretty) {
          renderPreviewOwnership(checks, summary, preloadErrorsObj, uniqueCounts);
          process.exit(EXIT.OK);
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
              unique_counts: uniqueCounts,
              preload_errors: preloadErrorsObj,
            },
            next_actions: nextActions,
          }),
          EXIT.OK,
        );
      },
    );

  program
    .command("status")
    .alias("ps")
    .description("list rotations in flight; pass a rotation-id for details")
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
      const inFlight = checkpoints.map((c) => ({
        rotation_id: c.rotationId,
        secret_id: c.rotation.secretId,
        status: c.rotation.status,
        step_completed: c.stepCompleted,
        grace_period_ends: c.rotation.gracePeriodEndsAt,
      }));
      if (shouldRenderPretty(program)) {
        renderStatusList(inFlight);
        process.exit(EXIT.OK);
      }
      emit(
        makeEnvelope({
          command: "status",
          status: "success",
          startedAt: started,
          agentMode: isAgentMode(),
          data: { in_flight: inFlight },
          next_actions: checkpoints.length
            ? [
                `${checkpoints.length} rotation(s) in flight; inspect via \`rotate-cli status <id>\``,
              ]
            : ["No rotations in flight"],
        }),
        EXIT.OK,
      );
    });

  program
    .command("revoke")
    .description("close a rotation: invalidate the old secret (after grace period)")
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
      if (shouldRenderPretty(program)) {
        renderRevoke(rotationId);
        process.exit(EXIT.OK);
      }
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
    .description("run an incident response: rotate everything matching the scope")
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
  return renderShouldPretty(program.opts<{ json?: boolean; pretty?: boolean }>());
}

// Convenience helper for audit-log append from tests.
export { appendAudit };

/**
 * Load secrets for --from-scan. Uses the cached scan if present and fresh,
 * re-scans otherwise. Honors selector filters (ids, provider, tag).
 */
async function loadFromScan(args: {
  ids: string[];
  provider?: string;
  tag?: string;
  fresh: boolean;
  maxAge: string;
}): Promise<Array<ReturnType<typeof filterSelectedFromCache>[number]>> {
  let cache = args.fresh ? null : readScanCache();
  const maxAgeMs = parseDurationMs(args.maxAge);

  if (!cache || scanCacheAgeMs(cache) > maxAgeMs) {
    const token = resolveVercelTokenForScan();
    if (!token) {
      throw new Error(
        "VERCEL_TOKEN missing. Set it or run `rotate-cli scan` with credentials available.",
      );
    }
    const result = await scanVercel({ token });
    const byAdapter: Record<string, number> = {};
    for (const s of result.secrets) byAdapter[s.adapter] = (byAdapter[s.adapter] ?? 0) + 1;
    writeScanCache({
      version: 1,
      generatedAt: new Date().toISOString(),
      teamsScanned: result.teamsScanned,
      projectsScanned: result.projectsScanned,
      totalSecrets: result.secrets.length,
      totalSkipped: result.skipped.length,
      byAdapter,
      secrets: result.secrets,
      skipped: result.skipped,
    });
    cache = readScanCache();
  }
  if (!cache) return [];
  return filterSelectedFromCache(cache, args);
}

function filterSelectedFromCache(
  cache: import("./scan-cache.ts").ScanCacheFile,
  args: { ids: string[]; provider?: string; tag?: string },
) {
  return cache.secrets.filter((s) => {
    if (args.provider && s.adapter !== args.provider) return false;
    if (args.tag && !(s.tags ?? []).includes(args.tag)) return false;
    if (args.ids.length > 0) {
      const canonical = `${s.adapter}/${s.id}`;
      if (!args.ids.includes(s.id) && !args.ids.includes(canonical)) return false;
    }
    return true;
  });
}

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

function summarizePreload(preload: Record<string, unknown>): string | undefined {
  const userId = typeof preload.userId === "string" ? preload.userId : undefined;
  if (userId) return `user ${userId.slice(0, 12)}`;
  const orgs = preload.organizations;
  if (Array.isArray(orgs)) return `${orgs.length} org(s)`;
  const workspaces = preload.workspaces;
  if (Array.isArray(workspaces)) return `${workspaces.length} workspace(s)`;
  const teams = preload.teams;
  if (Array.isArray(teams)) return `${teams.length} team(s)`;
  return undefined;
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
