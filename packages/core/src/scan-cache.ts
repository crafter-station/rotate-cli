/**
 * Persist the last `rotate-cli scan` result to ~/.config/rotate-cli/last-scan.json
 * so subsequent commands (who --from-scan, apply --from-scan) can consume it
 * without re-hitting Vercel.
 *
 * What's stored: secret metadata (provider, project, env var name, team id).
 * NOT stored: secret values. The cache is safe to cat/diff/commit-by-accident
 * — there's nothing sensitive to leak beyond "which env vars exist where",
 * which the Vercel UI also shows anyone with access to the project.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ScannedSecret } from "./scan.ts";

export interface ScanCacheFile {
  version: 1;
  generatedAt: string;
  teamsScanned: string[];
  projectsScanned: number;
  totalSecrets: number;
  totalSkipped: number;
  byAdapter: Record<string, number>;
  secrets: ScannedSecret[];
  skipped: Array<{ var_name: string; project: string; reason: string }>;
}

function getStateDir(): string {
  const configured = process.env.ROTATE_CLI_STATE_DIR;
  if (configured) return configured;
  const home = process.env.HOME;
  if (!home) throw new Error("HOME is not set — cannot resolve rotate-cli state dir");
  return join(home, ".config", "rotate-cli");
}

export function scanCachePath(): string {
  return join(getStateDir(), "last-scan.json");
}

export function writeScanCache(data: ScanCacheFile): string {
  const path = scanCachePath();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(data, null, 2), "utf8");
  try {
    chmodSync(path, 0o600);
  } catch {
    // best-effort — some filesystems don't support chmod (Windows, WSL mounts)
  }
  return path;
}

export function readScanCache(): ScanCacheFile | null {
  const path = scanCachePath();
  if (!existsSync(path)) return null;
  try {
    const raw = readFileSync(path, "utf8");
    const parsed = JSON.parse(raw) as ScanCacheFile;
    if (parsed.version !== 1) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function scanCacheAgeMs(cache: ScanCacheFile): number {
  return Date.now() - new Date(cache.generatedAt).getTime();
}

/**
 * Parse a duration string (e.g. "15m", "1h", "30s") into milliseconds.
 * Same grammar as `config.parseDuration` but exported separately to avoid
 * a dependency cycle between scan-cache and config.
 */
export function parseDurationMs(input: string): number {
  const match = /^(\d+)(ms|s|m|h|d)$/.exec(input.trim());
  if (!match) throw new Error(`invalid duration: ${input}`);
  const n = Number(match[1]);
  switch (match[2]) {
    case "ms":
      return n;
    case "s":
      return n * 1_000;
    case "m":
      return n * 60_000;
    case "h":
      return n * 3_600_000;
    case "d":
      return n * 86_400_000;
    default:
      throw new Error(`invalid duration: ${input}`);
  }
}

/** Default staleness threshold if neither flag nor env override is set. */
export const DEFAULT_SCAN_MAX_AGE = "15m";
