/**
 * Human pretty renderers for rotate-cli commands. Used when stdout is a TTY
 * and the user didn't pass --json. Agent mode + piped stdout always emit the
 * JSON envelope instead.
 *
 * Style matches sibling Crafter CLIs (spoti-cli, sunat-cli, onpe-cli):
 *   - No heavy frames — tight lists with 2-space indent
 *   - Status glyphs: ✓ (ok), ✗ (fail), ? (unknown), → (action)
 *   - picocolors for accents; never fall back to ANSI raw
 *   - Single blank line between sections, "Next:" hint at the end
 */

import pc from "picocolors";

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

export interface DoctorRow {
  kind: string;
  name: string;
  ok: boolean;
  mode?: "auto" | "manual-assist" | "no-check";
  authStatus?: "ok" | "missing" | "not-required";
  error?: string;
}

export function renderDoctor(rows: DoctorRow[]): void {
  const adapters = rows.filter((r) => r.kind === "adapter");
  const consumers = rows.filter((r) => r.kind === "consumer");
  const blocking = rows.filter((r) => r.authStatus === "missing");

  const authOk = rows.filter((r) => r.authStatus === "ok").length;
  const authBypass = rows.filter((r) => r.authStatus === "not-required").length;

  print(pc.bold("rotate-cli doctor"));
  print("");
  print(
    `${authOk} authenticated, ${authBypass} not required (${adapters.length} adapters, ${consumers.length} consumers)`,
  );
  print("");

  print(pc.dim("Adapters"));
  for (const r of adapters) {
    const glyph = glyphFor(r);
    const tag = tagFor(r);
    const suffix = r.authStatus === "missing" ? pc.dim(`, ${truncate(r.error ?? "", 60)}`) : "";
    print(`  ${glyph} ${r.name.padEnd(22)} ${tag}${suffix}`);
  }

  if (consumers.length > 0) {
    print("");
    print(pc.dim("Consumers"));
    for (const r of consumers) {
      const glyph = glyphFor(r);
      const suffix = r.authStatus === "missing" ? pc.dim(`, ${truncate(r.error ?? "", 60)}`) : "";
      print(`  ${glyph} ${r.name}${suffix}`);
    }
  }

  if (blocking.length > 0) {
    print("");
    print(pc.dim("Next:"));
    for (const f of blocking) {
      print(`  ${pc.yellow("→")} rotate-cli auth login ${f.name}`);
    }
  }

  const manualCount = adapters.filter((r) => r.mode === "manual-assist").length;
  if (manualCount > 0) {
    print("");
    print(
      pc.dim(
        `Note: ${manualCount} manual-assist adapter(s) shown as ○ need no pre-configured auth. You paste a fresh secret during each \`apply --manual-only\`.`,
      ),
    );
  }
}

function glyphFor(r: DoctorRow): string {
  if (r.authStatus === "ok") return pc.green("✓");
  if (r.authStatus === "not-required") return pc.dim("○");
  return pc.red("✗");
}

function tagFor(r: DoctorRow): string {
  if (!r.mode || r.mode === "auto") return "";
  if (r.mode === "manual-assist") return pc.dim("[manual-assist]");
  return pc.dim("[no-check]");
}

// ---------------------------------------------------------------------------
// preview-ownership
// ---------------------------------------------------------------------------

export interface OwnershipCheck {
  secret_id: string;
  adapter: string;
  verdict: "self" | "other" | "unknown" | null;
  admin_can_bill?: boolean;
  scope?: string;
  confidence?: string;
  strategy?: string;
  evidence?: string;
  reason?: string;
}

export interface OwnershipSummary {
  self: number;
  other: number;
  unknown: number;
  not_checked: number;
}

export function renderPreviewOwnership(
  checks: OwnershipCheck[],
  summary: OwnershipSummary,
  preloadErrors: Record<string, string>,
  uniqueCounts?: { self: number; other: number },
): void {
  print(pc.bold("rotate-cli preview-ownership"));
  print("");
  print(`${checks.length} secret(s) checked`);
  print("");

  const widest = Math.min(36, Math.max(20, ...checks.map((c) => c.secret_id.length)));

  for (const c of checks) {
    const verdict = c.verdict ?? "none";
    const glyph = {
      self: pc.green("✓"),
      other: pc.red("✗"),
      unknown: pc.yellow("?"),
      none: pc.dim("○"),
    }[verdict];
    const verdictLabel = {
      self: pc.green("self"),
      other: pc.red("other"),
      unknown: pc.yellow("unknown"),
      none: pc.dim("no-check"),
    }[verdict];
    const note = c.evidence ?? c.reason ?? "";
    const id = c.secret_id.padEnd(widest);
    const adapter = pc.dim(`[${c.adapter}]`);
    print(`  ${glyph} ${id} ${verdictLabel.padEnd(18)} ${adapter} ${pc.dim(truncate(note, 50))}`);
  }

  print("");
  const parts: string[] = [];
  if (summary.self > 0) {
    const suffix =
      uniqueCounts && uniqueCounts.self > 0 && uniqueCounts.self < summary.self
        ? pc.dim(` (${uniqueCounts.self} unique)`)
        : "";
    parts.push(`${pc.green(String(summary.self))} self${suffix}`);
  }
  if (summary.other > 0) {
    const suffix =
      uniqueCounts && uniqueCounts.other > 0 && uniqueCounts.other < summary.other
        ? pc.dim(` (${uniqueCounts.other} unique)`)
        : "";
    parts.push(`${pc.red(String(summary.other))} other${suffix}`);
  }
  if (summary.unknown > 0) parts.push(`${pc.yellow(String(summary.unknown))} unknown`);
  if (summary.not_checked > 0) parts.push(`${pc.dim(String(summary.not_checked))} no-check`);
  print(`Summary: ${parts.join(", ")}`);

  if (Object.keys(preloadErrors).length > 0) {
    print("");
    print(pc.dim("Preload errors:"));
    for (const [adapter, err] of Object.entries(preloadErrors)) {
      print(`  ${pc.red("✗")} ${adapter}: ${pc.dim(truncate(err, 60))}`);
    }
  }

  print("");
  print(pc.dim("Next:"));
  if (summary.self > 0) {
    print(`  ${pc.cyan("→")} rotate-cli apply <id> --yes --reason "..."`);
  }
  if (summary.other > 0) {
    print(
      `  ${pc.cyan("→")} coordinate with the owner, or --force-rotate-other to override (changes billing)`,
    );
  }
  if (summary.unknown > 0) {
    print(`  ${pc.cyan("→")} add currentValueEnv hints in rotate.config.yaml`);
  }
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

export interface PlanItem {
  id: string;
  adapter: string;
  consumer_count: number;
  consumers: Array<{ type: string; params: Record<string, string> }>;
}

export function renderPlan(selected: PlanItem[]): void {
  print(pc.bold("rotate-cli plan"));
  print("");

  if (!selected.length) {
    print(pc.yellow("No secrets matched the selector."));
    return;
  }

  print(`${selected.length} secret(s) would be rotated`);
  print("");

  for (const s of selected) {
    print(`  ${pc.cyan("●")} ${pc.bold(s.id)} ${pc.dim(`[${s.adapter}]`)}`);
    for (const c of s.consumers) {
      const detail = c.params.var_name
        ? `${c.params.var_name} in ${c.params.project ?? c.params.repo ?? c.params.path}`
        : JSON.stringify(c.params);
      print(`      ${pc.dim("↳")} ${c.type} ${pc.dim(detail)}`);
    }
  }

  print("");
  print(pc.dim("Next:"));
  const ids = selected.map((s) => s.id).join(" ");
  print(`  ${pc.cyan("→")} rotate-cli apply ${ids} --yes --reason "..."`);
}

// ---------------------------------------------------------------------------
// apply / incident
// ---------------------------------------------------------------------------

export interface RotationResult {
  rotation_id?: string;
  secret_id: string;
  status: string;
  grace_period_ends?: string;
  consumers?: Array<{ target: { type: string; params: Record<string, string> }; status: string }>;
}

export interface SkipEntry {
  secret_id: string;
  adapter: string;
  reason?: string;
  evidence?: string;
  verdict?: string;
}

export interface ApplyRunSummary {
  rotated: number;
  skipped: number;
  failed: number;
  /** The original pre-rotation ownership verdicts captured during who. */
  ownership?: OwnershipSummary;
}

export interface RenderApplyOptions {
  /** Unroll every rotated/skipped row. Default: false — summary view only. */
  verbose?: boolean;
  /** Cap on how many rows per bucket the summary view prints. Default 5. */
  summaryLimit?: number;
}

export function renderApply(
  rotations: RotationResult[],
  skipped: SkipEntry[],
  summary: ApplyRunSummary,
  nextActions: string[],
  opts: RenderApplyOptions = {},
): void {
  const verbose = opts.verbose ?? false;
  const limit = opts.summaryLimit ?? 5;
  const total = summary.rotated + summary.skipped + summary.failed;

  print(pc.bold("rotate-cli apply"));
  print("");

  // Summary line is the headline. Humans see one number per bucket, colored.
  const headlineParts: string[] = [];
  if (summary.rotated > 0) headlineParts.push(pc.green(`${summary.rotated} rotated`));
  if (summary.skipped > 0) headlineParts.push(pc.yellow(`${summary.skipped} skipped`));
  if (summary.failed > 0) headlineParts.push(pc.red(`${summary.failed} failed`));
  if (total === 0) headlineParts.push(pc.dim("nothing to do"));
  print(`${headlineParts.join("  ·  ")}  ${pc.dim(`(${total} total)`)}`);

  // Break the skipped bucket down by reason. Most rotations skip for only
  // 2-3 distinct reasons (ownership-other dominates); this lets the user
  // see at a glance what kind of manual follow-up they need.
  if (summary.skipped > 0) {
    print("");
    const byReason = groupBy(skipped, (s) => s.reason ?? "unknown");
    const reasonOrder = [
      "ownership-other",
      "ownership-unknown-skipped",
      "ownership-self-member-only",
      "ownership-current-value-unavailable",
      "adapter-missing-metadata",
    ];
    const sortedReasons = Object.keys(byReason).sort((a, b) => {
      const ai = reasonOrder.indexOf(a);
      const bi = reasonOrder.indexOf(b);
      if (ai === -1 && bi === -1) return a.localeCompare(b);
      if (ai === -1) return 1;
      if (bi === -1) return -1;
      return ai - bi;
    });
    for (const reason of sortedReasons) {
      const group = byReason[reason]!;
      const label =
        {
          "ownership-other": "not yours",
          "ownership-self-member-only": "not an admin",
          "ownership-unknown-skipped": "ownership unknown",
          "ownership-current-value-unavailable": "no current value",
          "adapter-missing-metadata": "needs metadata",
        }[reason] ?? reason;
      print(`  ${pc.yellow("○")} ${label.padEnd(22)} ${pc.dim(`× ${group.length}`)}`);
    }
  }

  // Provider breakdown for rotated secrets. One line per provider.
  if (summary.rotated > 0) {
    print("");
    const byProvider = groupBy(rotations, (r) => providerOf(r.secret_id));
    const sorted = Object.keys(byProvider).sort();
    for (const provider of sorted) {
      const group = byProvider[provider]!;
      const inGrace = group.filter((r) => r.grace_period_ends).length;
      const graceSuffix = inGrace > 0 ? pc.dim(` (${inGrace} in grace)`) : "";
      print(
        `  ${pc.green("✓")} ${provider.padEnd(22)} ${pc.dim(`× ${group.length}`)}${graceSuffix}`,
      );
    }
  }

  // Verbose mode (or when the total is tiny): show each row. Otherwise
  // just the first N per bucket as a sample.
  const showAll = verbose || total <= limit * 2;

  if (rotations.length > 0 && (showAll || verbose)) {
    print("");
    print(pc.dim(`Rotated ${rotations.length}:`));
    const rows = showAll ? rotations : rotations.slice(0, limit);
    for (const r of rows) {
      const graceBit = r.grace_period_ends
        ? pc.dim(` · grace ${r.grace_period_ends.slice(11, 16)}Z`)
        : "";
      print(`  ${pc.green("●")} ${r.secret_id}${graceBit}`);
    }
    if (!showAll && rotations.length > limit) {
      print(pc.dim(`    … +${rotations.length - limit} more (rerun with --verbose to see all)`));
    }
  }

  if (skipped.length > 0 && verbose) {
    print("");
    print(pc.dim(`Skipped ${skipped.length}:`));
    for (const s of skipped) {
      const kindLabel =
        {
          "ownership-other": pc.red("other"),
          "ownership-self-member-only": pc.yellow("self(member)"),
          "ownership-unknown-skipped": pc.yellow("unknown"),
          "ownership-current-value-unavailable": pc.dim("no-current-value"),
          "adapter-missing-metadata": pc.yellow("needs-metadata"),
        }[s.reason ?? ""] ?? pc.dim(s.reason ?? "");
      print(`  ${pc.yellow("○")} ${s.secret_id} ${kindLabel}`);
      if (s.evidence) print(`      ${pc.dim(truncate(s.evidence, 80))}`);
    }
  }

  if (nextActions.length > 0) {
    print("");
    print(pc.dim("Next:"));
    const shown = verbose ? nextActions : nextActions.slice(0, 4);
    for (const a of shown) {
      // nextActions can carry long comma-separated secret lists for the
      // "belong to another account" hint. Collapse to the first line + count.
      print(`  ${pc.cyan("→")} ${truncate(a, 140)}`);
    }
    if (!verbose && nextActions.length > 4) {
      print(pc.dim(`    … +${nextActions.length - 4} more hint(s) (--verbose for all)`));
    }
  }
}

function groupBy<T>(items: T[], key: (t: T) => string): Record<string, T[]> {
  const out: Record<string, T[]> = {};
  for (const item of items) {
    const k = key(item);
    const bucket = out[k] ?? [];
    bucket.push(item);
    out[k] = bucket;
  }
  return out;
}

function providerOf(secretId: string): string {
  // secret_id format is `{adapter}-{project}-{VAR_NAME}`. Take the adapter
  // part (may itself contain hyphens: "neon-connection", "vercel-ai-gateway").
  // Heuristic: match against known multi-word adapter prefixes first, else
  // take everything before the first `-`.
  const knownPrefixes = [
    "neon-connection",
    "vercel-ai-gateway",
    "vercel-blob",
    "vercel-kv",
    "vercel-token",
    "local-random",
    "trigger-dev",
    "github-token",
    "fal-ai",
  ];
  for (const prefix of knownPrefixes) {
    if (secretId.startsWith(`${prefix}-`)) return prefix;
  }
  const dash = secretId.indexOf("-");
  return dash === -1 ? secretId : secretId.slice(0, dash);
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

export interface StatusEntry {
  rotation_id: string;
  secret_id: string;
  status: string;
  step_completed?: string;
  grace_period_ends?: string;
}

export function renderStatusList(inFlight: StatusEntry[]): void {
  print(pc.bold("rotate-cli status"));
  print("");
  if (!inFlight.length) {
    print(pc.dim("No rotations in flight."));
    return;
  }
  print(`${inFlight.length} rotation(s) in flight`);
  print("");
  for (const r of inFlight) {
    const statusColor =
      r.status === "in_grace" ? pc.green : r.status === "failed" ? pc.red : pc.yellow;
    print(
      `  ${pc.cyan("●")} ${pc.bold(r.rotation_id)} ${statusColor(r.status)} ${pc.dim(r.secret_id)}`,
    );
    if (r.grace_period_ends) {
      print(`      ${pc.dim(`grace ends ${r.grace_period_ends.slice(0, 16)} UTC`)}`);
    }
  }
  print("");
  print(pc.dim("Next:"));
  print(`  ${pc.cyan("→")} rotate-cli revoke <rotation-id>  when consumers are synced`);
}

// ---------------------------------------------------------------------------
// revoke
// ---------------------------------------------------------------------------

export function renderRevoke(rotationId: string): void {
  print(pc.bold("rotate-cli revoke"));
  print("");
  print(`  ${pc.green("✓")} ${pc.bold(rotationId)} closed`);
  print(`      ${pc.dim("old secret invalidated; grace period ended")}`);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function print(line: string): void {
  process.stdout.write(`${line}\n`);
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/**
 * Decide between pretty human output and JSON envelope.
 *
 * - Explicit flags win: --json → JSON, --pretty → pretty.
 * - Agent mode always emits JSON.
 * - Piped stdout → JSON (cheaper for agents to parse).
 * - Interactive TTY → pretty.
 */
// ---------------------------------------------------------------------------
// scan live progress
// ---------------------------------------------------------------------------

/**
 * Renders a live, in-place scan progress tracker. The active team gets an
 * animated spinner line that updates in place; completed teams fall through
 * as a static line above.
 *
 * Not used when stdout is not a TTY — the caller falls back to the JSON
 * envelope in that case.
 */
export function createScanProgressRenderer(): {
  handle: (event: import("./scan.ts").ScanProgressEvent) => void;
  stop: () => void;
} {
  const spinnerFrames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  const isTTY = Boolean(process.stdout.isTTY);
  let frame = 0;
  let active: {
    team: string;
    totalProjects: number;
    projectsScanned: number;
    secretsSoFar: number;
  } | null = null;
  let spinnerActive = false;

  const interval = isTTY
    ? setInterval(() => {
        frame = (frame + 1) % spinnerFrames.length;
        if (active) drawActive();
      }, 80)
    : null;

  function clearSpinnerLine(): void {
    if (!isTTY || !spinnerActive) return;
    // \r returns to column 0, \x1b[2K erases the entire line (safer than \x1b[K).
    process.stdout.write("\r\x1b[2K");
    spinnerActive = false;
  }

  function drawActive(): void {
    if (!active || !isTTY) return;
    clearSpinnerLine();
    const spin = pc.cyan(spinnerFrames[frame]);
    const progress = pc.dim(`${active.projectsScanned}/${active.totalProjects}`);
    const secrets = active.secretsSoFar > 0 ? pc.dim(` · ${active.secretsSoFar} secrets`) : "";
    process.stdout.write(`  ${spin} ${active.team.padEnd(20)} ${progress}${secrets}`);
    spinnerActive = true;
  }

  function writeStaticLine(line: string): void {
    clearSpinnerLine();
    process.stdout.write(`${line}\n`);
    if (active) drawActive();
  }

  function handle(event: import("./scan.ts").ScanProgressEvent): void {
    if (event.kind === "teams-discovered") {
      writeStaticLine(
        `${pc.bold("rotate-cli scan")}\n\nScanning ${event.teams.length} scope(s)...\n`,
      );
    } else if (event.kind === "team-start") {
      active = {
        team: event.team,
        totalProjects: event.totalProjects,
        projectsScanned: 0,
        secretsSoFar: 0,
      };
      drawActive();
    } else if (event.kind === "team-progress") {
      if (active && active.team === event.team) {
        active.projectsScanned = event.projectsScanned;
        active.secretsSoFar = event.secretsSoFar;
        drawActive();
      }
    } else if (event.kind === "team-done") {
      active = null;
      const duration =
        event.durationMs > 1000
          ? `${(event.durationMs / 1000).toFixed(1)}s`
          : `${event.durationMs}ms`;
      writeStaticLine(
        `  ${pc.green("✓")} ${event.team.padEnd(20)} ${event.projectsScanned} projects ${pc.dim(`· ${event.secretsFound} secrets · ${duration}`)}`,
      );
    } else if (event.kind === "team-skipped") {
      active = null;
      writeStaticLine(
        `  ${pc.yellow("⚠")} ${event.team.padEnd(20)} ${pc.dim(`skipped (${event.reason})`)}`,
      );
    }
  }

  function stop(): void {
    if (interval) clearInterval(interval);
    clearSpinnerLine();
    active = null;
  }

  return { handle, stop };
}

export function renderScanSummary(data: {
  projectsScanned: number;
  teamsScanned: number;
  totalSecrets: number;
  totalSkipped: number;
  byAdapter: Record<string, number>;
}): void {
  print("");
  print(
    `${pc.bold("Total:")} ${data.projectsScanned} projects · ${pc.green(String(data.totalSecrets))} mapped · ${pc.dim(`${data.totalSkipped} unmapped`)}`,
  );
  print("");
  print(pc.dim("Mapped by adapter:"));
  const sorted = Object.entries(data.byAdapter).sort((a, b) => b[1] - a[1]);
  for (const [adapter, count] of sorted) {
    print(`  ${String(count).padStart(4)}  ${adapter}`);
  }
  print("");
  print(pc.dim("Next:"));
  print(
    `  ${pc.cyan("→")} rotate-cli who --from-scan           ${pc.dim("# ownership check every mapped secret")}`,
  );
  print(
    `  ${pc.cyan("→")} rotate-cli apply --from-scan --yes   ${pc.dim("# bulk rotate your-owned secrets")}`,
  );
}

// ---------------------------------------------------------------------------
// who (preview-ownership) — live 2-phase progress
// ---------------------------------------------------------------------------

export type OwnershipProgressEvent =
  | { kind: "preload-start"; adapters: string[] }
  | { kind: "preload-done"; adapter: string; durationMs: number; info?: string }
  | { kind: "preload-failed"; adapter: string; durationMs: number; error: string }
  | { kind: "check-start"; total: number }
  | {
      kind: "check-progress";
      done: number;
      total: number;
      self: number;
      other: number;
      unknown: number;
      notChecked: number;
    };

export function createOwnershipProgressRenderer(): {
  handle: (event: OwnershipProgressEvent) => void;
  stop: () => void;
} {
  const frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  const isTTY = Boolean(process.stdout.isTTY);
  let frame = 0;
  let activeLine = "";
  let lineActive = false;
  const startedAt = Date.now();

  const interval = isTTY
    ? setInterval(() => {
        frame = (frame + 1) % frames.length;
        if (activeLine) redraw();
      }, 80)
    : null;

  function clearLine(): void {
    if (!isTTY || !lineActive) return;
    process.stdout.write("\r\x1b[2K");
    lineActive = false;
  }

  function redraw(): void {
    if (!isTTY || !activeLine) return;
    clearLine();
    process.stdout.write(activeLine.replace("__SPIN__", pc.cyan(frames[frame]!)));
    lineActive = true;
  }

  function writeStatic(line: string): void {
    clearLine();
    process.stdout.write(`${line}\n`);
    if (activeLine) redraw();
  }

  function bar(pct: number, width = 24): string {
    const filled = Math.max(0, Math.min(width, Math.round(pct * width)));
    return pc.cyan("█".repeat(filled)) + pc.dim("░".repeat(width - filled));
  }

  function handle(event: OwnershipProgressEvent): void {
    if (event.kind === "preload-start") {
      writeStatic(`${pc.bold("rotate-cli who")}\n\nPreloading ownership indexes...`);
    } else if (event.kind === "preload-done") {
      const duration =
        event.durationMs > 1000
          ? `${(event.durationMs / 1000).toFixed(1)}s`
          : `${event.durationMs}ms`;
      const info = event.info ? pc.dim(`· ${event.info}`) : "";
      writeStatic(
        `  ${pc.green("✓")} ${event.adapter.padEnd(20)} ${info} ${pc.dim(`· ${duration}`)}`,
      );
    } else if (event.kind === "preload-failed") {
      writeStatic(
        `  ${pc.yellow("⚠")} ${event.adapter.padEnd(20)} ${pc.dim(`· ${event.error.slice(0, 50)}`)}`,
      );
    } else if (event.kind === "check-start") {
      writeStatic(`\nChecking ${event.total} secret(s)...`);
      activeLine = `  __SPIN__ ${bar(0)}  0/${event.total}`;
      redraw();
    } else if (event.kind === "check-progress") {
      const pct = event.total > 0 ? event.done / event.total : 0;
      const elapsed = (Date.now() - startedAt) / 1000;
      const rate = elapsed > 0 ? Math.round(event.done / elapsed) : 0;
      const counters: string[] = [];
      if (event.self > 0) counters.push(pc.green(`${event.self} self`));
      if (event.other > 0) counters.push(pc.red(`${event.other} other`));
      if (event.unknown > 0) counters.push(pc.yellow(`${event.unknown} unknown`));
      if (event.notChecked > 0) counters.push(pc.dim(`${event.notChecked} no-check`));
      const counterStr = counters.length > 0 ? `  ${counters.join(" · ")}` : "";
      const rateStr = rate > 0 ? pc.dim(` · ${rate}/s`) : "";
      activeLine = `  __SPIN__ ${bar(pct)}  ${event.done}/${event.total}${counterStr}${rateStr}`;
      redraw();
    }
  }

  function stop(): void {
    if (interval) clearInterval(interval);
    clearLine();
    activeLine = "";
  }

  return { handle, stop };
}

// ---------------------------------------------------------------------------
// apply — per-rotation progress
// ---------------------------------------------------------------------------

export type ApplyProgressEvent =
  | { kind: "preload-start"; adapters: string[] }
  | { kind: "preload-done"; adapter: string; durationMs: number; info?: string }
  | { kind: "preload-failed"; adapter: string; durationMs: number; error: string }
  | { kind: "siblings-start"; totalProjects: number }
  | {
      kind: "siblings-progress";
      completed: number;
      total: number;
      decrypted: number;
      currentSlug?: string;
    }
  | { kind: "siblings-done"; decrypted: number; totalProjects: number; durationMs: number }
  | { kind: "resolving-start"; total: number }
  | { kind: "resolving-progress"; done: number; total: number; resolved: number }
  | { kind: "resolving-done"; resolved: number; total: number; durationMs: number }
  | { kind: "dedup"; totalEntries: number; uniqueGroups: number }
  | { kind: "start"; total: number }
  | { kind: "rotation-start"; index: number; total: number; secretId: string; adapter: string }
  | {
      kind: "rotation-step";
      index: number;
      step: "ownership" | "create" | "propagate" | "trigger" | "verify";
    }
  | {
      kind: "rotation-consumer-progress";
      index: number;
      step: "propagate" | "trigger" | "verify";
      done: number;
      total: number;
    }
  | {
      kind: "rotation-done";
      index: number;
      total: number;
      secretId: string;
      status: "success" | "partial" | "error" | "skipped";
      rotationId?: string;
      durationMs: number;
      note?: string;
    };

export function createApplyProgressRenderer(): {
  handle: (event: ApplyProgressEvent) => void;
  stop: () => void;
} {
  const frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  const isTTY = Boolean(process.stdout.isTTY);
  let frame = 0;
  let active: {
    index: number;
    total: number;
    secretId: string;
    adapter: string;
    step: string;
    consumerDone?: number;
    consumerTotal?: number;
  } | null = null;
  let siblings: {
    completed: number;
    total: number;
    decrypted: number;
    currentSlug?: string;
  } | null = null;
  let resolving: {
    done: number;
    total: number;
    resolved: number;
  } | null = null;
  let lineActive = false;
  const siblingsStartedAt = { ts: 0 };
  const resolvingStartedAt = { ts: 0 };

  const interval = isTTY
    ? setInterval(() => {
        frame = (frame + 1) % frames.length;
        if (active) drawActive();
        else if (siblings) drawSiblings();
        else if (resolving) drawResolving();
      }, 80)
    : null;

  function clearLine(): void {
    if (!isTTY || !lineActive) return;
    process.stdout.write("\r\x1b[2K");
    lineActive = false;
  }

  function bar(pct: number, width = 24): string {
    const filled = Math.max(0, Math.min(width, Math.round(pct * width)));
    return pc.cyan("█".repeat(filled)) + pc.dim("░".repeat(width - filled));
  }

  function termWidth(): number {
    return Math.max(40, process.stdout.columns ?? 120);
  }

  const ESC = String.fromCharCode(0x1b);
  const ANSI_RE = new RegExp(`${ESC}\\[[0-9;]*m`, "g");

  function fitLine(text: string, max?: number): string {
    const limit = max ?? termWidth() - 2;
    // Strip ANSI color codes to measure length, but don't strip when truncating.
    const stripped = text.replace(ANSI_RE, "");
    if (stripped.length <= limit) return text;
    // Cheap safe truncation: rebuild char-by-char until we hit the cap.
    let out = "";
    let visible = 0;
    let i = 0;
    while (i < text.length && visible < limit - 1) {
      if (text[i] === ESC && text[i + 1] === "[") {
        const end = text.indexOf("m", i);
        if (end > -1) {
          out += text.slice(i, end + 1);
          i = end + 1;
          continue;
        }
      }
      out += text[i];
      visible++;
      i++;
    }
    return `${out}…`;
  }

  function drawActive(): void {
    if (!active || !isTTY) return;
    clearLine();
    const spin = pc.cyan(frames[frame]);
    const progress = pc.dim(`[${active.index}/${active.total}]`);
    const consumerPart =
      active.consumerDone !== undefined && active.consumerTotal !== undefined
        ? pc.dim(` (${active.consumerDone}/${active.consumerTotal})`)
        : "";
    const step = pc.dim(`${active.step}${consumerPart}`);
    // Truncate the secretId so the whole line stays on a single row — prevents
    // the spinner from wrapping and leaving stale text behind on redraw.
    const idBudget = Math.max(20, termWidth() - 30 - active.adapter.length - active.step.length);
    const secret =
      active.secretId.length > idBudget
        ? `${active.secretId.slice(0, idBudget - 1)}…`
        : active.secretId.padEnd(Math.min(idBudget, 30));
    process.stdout.write(
      fitLine(`  ${spin} ${progress} ${secret} ${pc.dim(`[${active.adapter}]`)} ${step}`),
    );
    lineActive = true;
  }

  function drawSiblings(): void {
    if (!siblings || !isTTY) return;
    clearLine();
    const spin = pc.cyan(frames[frame]);
    const pct = siblings.total > 0 ? siblings.completed / siblings.total : 0;
    const elapsed = siblingsStartedAt.ts > 0 ? (Date.now() - siblingsStartedAt.ts) / 1000 : 0;
    const rate = elapsed > 0 ? Math.round(siblings.completed / elapsed) : 0;
    const decrypted = pc.dim(`· ${siblings.decrypted} decrypted`);
    const rateStr = rate > 0 ? pc.dim(` · ${rate}/s`) : "";
    process.stdout.write(
      fitLine(
        `  ${spin} ${bar(pct)}  ${siblings.completed}/${siblings.total} ${decrypted}${rateStr}`,
      ),
    );
    lineActive = true;
  }

  function drawResolving(): void {
    if (!resolving || !isTTY) return;
    clearLine();
    const spin = pc.cyan(frames[frame]);
    const pct = resolving.total > 0 ? resolving.done / resolving.total : 0;
    const elapsed = resolvingStartedAt.ts > 0 ? (Date.now() - resolvingStartedAt.ts) / 1000 : 0;
    const rate = elapsed > 0 ? Math.round(resolving.done / elapsed) : 0;
    const resolved = pc.dim(`· ${resolving.resolved} resolved`);
    const rateStr = rate > 0 ? pc.dim(` · ${rate}/s`) : "";
    process.stdout.write(
      fitLine(`  ${spin} ${bar(pct)}  ${resolving.done}/${resolving.total} ${resolved}${rateStr}`),
    );
    lineActive = true;
  }

  function writeStatic(line: string): void {
    clearLine();
    process.stdout.write(`${line}\n`);
    if (active) drawActive();
    else if (siblings) drawSiblings();
    else if (resolving) drawResolving();
  }

  function handle(event: ApplyProgressEvent): void {
    if (event.kind === "preload-start") {
      writeStatic(`${pc.bold("rotate-cli apply")}\n\nPreloading ownership indexes...`);
    } else if (event.kind === "preload-done") {
      const duration =
        event.durationMs > 1000
          ? `${(event.durationMs / 1000).toFixed(1)}s`
          : `${event.durationMs}ms`;
      const info = event.info ? pc.dim(`· ${event.info}`) : "";
      writeStatic(
        `  ${pc.green("✓")} ${event.adapter.padEnd(20)} ${info} ${pc.dim(`· ${duration}`)}`,
      );
    } else if (event.kind === "preload-failed") {
      writeStatic(
        `  ${pc.yellow("⚠")} ${event.adapter.padEnd(20)} ${pc.dim(`· ${event.error.slice(0, 50)}`)}`,
      );
    } else if (event.kind === "siblings-start") {
      writeStatic(
        `\nFetching co-located env vars from ${event.totalProjects} Vercel project(s)...`,
      );
      siblings = { completed: 0, total: event.totalProjects, decrypted: 0 };
      siblingsStartedAt.ts = Date.now();
      drawSiblings();
    } else if (event.kind === "siblings-progress") {
      if (siblings) {
        siblings.completed = event.completed;
        siblings.total = event.total;
        siblings.decrypted = event.decrypted;
        siblings.currentSlug = event.currentSlug;
        drawSiblings();
      }
    } else if (event.kind === "siblings-done") {
      siblings = null;
      const duration =
        event.durationMs > 1000
          ? `${(event.durationMs / 1000).toFixed(1)}s`
          : `${event.durationMs}ms`;
      writeStatic(
        `  ${pc.green("✓")} vercel-siblings     ${pc.dim(`· ${event.decrypted}/${event.totalProjects} decrypted · ${duration}`)}`,
      );
    } else if (event.kind === "resolving-start") {
      writeStatic(`\nResolving current values for ${event.total} secret(s)...`);
      resolving = { done: 0, total: event.total, resolved: 0 };
      resolvingStartedAt.ts = Date.now();
      drawResolving();
    } else if (event.kind === "resolving-progress") {
      if (resolving) {
        resolving.done = event.done;
        resolving.total = event.total;
        resolving.resolved = event.resolved;
        drawResolving();
      }
    } else if (event.kind === "resolving-done") {
      resolving = null;
      const duration =
        event.durationMs > 1000
          ? `${(event.durationMs / 1000).toFixed(1)}s`
          : `${event.durationMs}ms`;
      writeStatic(
        `  ${pc.green("✓")} current-values      ${pc.dim(`· ${event.resolved}/${event.total} resolved · ${duration}`)}`,
      );
    } else if (event.kind === "dedup") {
      if (event.uniqueGroups < event.totalEntries) {
        writeStatic(
          `\n${pc.dim(`Deduplicating: ${event.totalEntries} entries become ${event.uniqueGroups} unique rotation(s).`)}`,
        );
      }
    } else if (event.kind === "start") {
      writeStatic(`\nApplying ${event.total} rotation(s)...`);
    } else if (event.kind === "rotation-start") {
      active = {
        index: event.index,
        total: event.total,
        secretId: event.secretId,
        adapter: event.adapter,
        step: "starting...",
      };
      drawActive();
    } else if (event.kind === "rotation-step") {
      if (active && active.index === event.index) {
        active.step = `${event.step}...`;
        active.consumerDone = undefined;
        active.consumerTotal = undefined;
        drawActive();
      }
    } else if (event.kind === "rotation-consumer-progress") {
      if (active && active.index === event.index) {
        active.step = `${event.step}...`;
        active.consumerDone = event.done;
        active.consumerTotal = event.total;
        drawActive();
      }
    } else if (event.kind === "rotation-done") {
      active = null;
      const duration =
        event.durationMs > 1000
          ? `${(event.durationMs / 1000).toFixed(1)}s`
          : `${event.durationMs}ms`;
      const glyph = {
        success: pc.green("✓"),
        partial: pc.yellow("⚠"),
        error: pc.red("✗"),
        skipped: pc.dim("○"),
      }[event.status];
      const label = {
        success: pc.green("rotated"),
        partial: pc.yellow("partial"),
        error: pc.red("failed"),
        skipped: pc.dim("skipped"),
      }[event.status];
      const idPart = event.rotationId ? pc.dim(` · ${event.rotationId}`) : "";
      const notePart = event.note ? pc.dim(` · ${event.note}`) : "";
      writeStatic(
        `  ${glyph} [${event.index}/${event.total}] ${pc.bold(event.secretId)} ${label}${idPart} ${pc.dim(`· ${duration}`)}${notePart}`,
      );
    }
  }

  function stop(): void {
    if (interval) clearInterval(interval);
    clearLine();
    active = null;
    siblings = null;
    resolving = null;
  }

  return { handle, stop };
}

export function shouldRenderPretty(opts: { json?: boolean; pretty?: boolean }): boolean {
  // Explicit flags always win.
  if (opts.json) return false;
  if (opts.pretty) return true;
  // Agent mode always emits JSON (rotate-cli's agent-first contract).
  if (process.env.ROTATE_CLI_AGENT_MODE === "1") return false;
  // Default: pretty. Matches sibling Crafter CLIs (spoti-cli, sunat-cli).
  // If you pipe the output into another tool, pass --json explicitly.
  return true;
}
