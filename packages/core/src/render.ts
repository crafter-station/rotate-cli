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
  error?: string;
}

export function renderDoctor(rows: DoctorRow[]): void {
  const adapters = rows.filter((r) => r.kind === "adapter");
  const consumers = rows.filter((r) => r.kind === "consumer");
  const failing = rows.filter((r) => !r.ok);

  const total = rows.length;
  const ok = rows.filter((r) => r.ok).length;

  print(pc.bold("rotate-cli doctor"));
  print("");
  print(
    `${ok}/${total} authenticated (${adapters.length} adapters, ${consumers.length} consumers)`,
  );
  print("");

  print(pc.dim("Adapters"));
  for (const r of adapters) {
    const glyph = r.ok ? pc.green("✓") : pc.red("✗");
    const suffix = r.ok ? "" : pc.dim(` — ${truncate(r.error ?? "", 60)}`);
    print(`  ${glyph} ${r.name}${suffix}`);
  }

  if (consumers.length > 0) {
    print("");
    print(pc.dim("Consumers"));
    for (const r of consumers) {
      const glyph = r.ok ? pc.green("✓") : pc.red("✗");
      const suffix = r.ok ? "" : pc.dim(` — ${truncate(r.error ?? "", 60)}`);
      print(`  ${glyph} ${r.name}${suffix}`);
    }
  }

  if (failing.length > 0) {
    print("");
    print(pc.dim("Next:"));
    for (const f of failing) {
      print(`  ${pc.yellow("→")} rotate-cli auth login ${f.name}`);
    }
  }
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
  if (summary.self > 0) parts.push(`${pc.green(String(summary.self))} self`);
  if (summary.other > 0) parts.push(`${pc.red(String(summary.other))} other`);
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

export function renderApply(
  rotations: RotationResult[],
  skipped: SkipEntry[],
  ownershipSummary: OwnershipSummary,
  nextActions: string[],
): void {
  print(pc.bold("rotate-cli apply"));
  print("");

  if (rotations.length > 0) {
    print(`${pc.green("✓")} ${rotations.length} secret(s) rotated`);
    for (const r of rotations) {
      print(`  ${pc.green("●")} ${pc.bold(r.secret_id)} ${pc.dim(r.rotation_id ?? "")}`);
      if (r.grace_period_ends) {
        print(`      ${pc.dim(`in grace until ${r.grace_period_ends.slice(11, 16)} UTC`)}`);
      }
      for (const c of r.consumers ?? []) {
        const glyph = c.status === "synced" ? pc.green("✓") : pc.yellow("…");
        print(`      ${glyph} ${c.target.type} ${pc.dim(c.target.params.var_name ?? "")}`);
      }
    }
  }

  if (skipped.length > 0) {
    print("");
    print(`${pc.yellow("⚠")} ${skipped.length} secret(s) skipped`);
    for (const s of skipped) {
      const kindLabel =
        {
          "ownership-other": pc.red("other"),
          "ownership-self-member-only": pc.yellow("self (not-admin)"),
          "ownership-unknown-skipped": pc.yellow("unknown"),
          "ownership-current-value-unavailable": pc.dim("no-current-value"),
        }[s.reason ?? ""] ?? pc.dim(s.reason ?? "");
      print(`  ${pc.yellow("○")} ${pc.bold(s.secret_id)} ${kindLabel}`);
      if (s.evidence) print(`      ${pc.dim(truncate(s.evidence, 70))}`);
    }
  }

  print("");
  const parts: string[] = [];
  if (ownershipSummary.self > 0) parts.push(`${pc.green(String(ownershipSummary.self))} self`);
  if (ownershipSummary.other > 0) parts.push(`${pc.red(String(ownershipSummary.other))} other`);
  if (ownershipSummary.unknown > 0)
    parts.push(`${pc.yellow(String(ownershipSummary.unknown))} unknown`);
  if (ownershipSummary.not_checked > 0)
    parts.push(`${pc.dim(String(ownershipSummary.not_checked))} no-check`);
  if (parts.length > 0) print(`Ownership: ${parts.join(", ")}`);

  if (nextActions.length > 0) {
    print("");
    print(pc.dim("Next:"));
    for (const a of nextActions) {
      print(`  ${pc.cyan("→")} ${a}`);
    }
  }
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
