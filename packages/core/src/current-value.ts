/**
 * Resolve the CURRENT value of a secret (before rotation) so the orchestrator
 * can hand it to `adapter.ownedBy()`.
 *
 * Resolution order:
 *   1. `secret.currentValueEnv`  → process.env[name]
 *   2. `secret.currentValue`     → literal (warns; testing only)
 *   3. Vercel pull               → GET /v9/projects/{id}/env/{id}?decrypt=true
 *      (only for consumers of type `vercel-env` with non-`sensitive` values)
 *   4. `{ value: null, source: "unavailable" }` — caller treats as unknown
 *
 * Never throws. Network errors are captured in `error` and the caller decides
 * whether to skip the rotation or proceed.
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import type { SecretConfig } from "./types.ts";

export type CurrentValueSource = "env" | "literal" | "vercel-api" | "unavailable" | "error";

export interface CurrentValueResolution {
  value: string | null;
  source: CurrentValueSource;
  /** Non-null when source === "error". Never thrown — always returned. */
  error?: string;
}

export async function resolveCurrentValue(
  secret: SecretConfig,
  opts?: { preFetchedVars?: Record<string, string> | undefined },
): Promise<CurrentValueResolution> {
  // 1. Explicit env var override.
  if (secret.currentValueEnv) {
    const v = process.env[secret.currentValueEnv];
    if (v && v.length > 0) {
      return { value: v, source: "env" };
    }
  }

  // 2. Literal (testing only — no warning emitted here, the config loader is
  //    the right layer for that since it sees every secret at load time).
  if (secret.currentValue && secret.currentValue.length > 0) {
    return { value: secret.currentValue, source: "literal" };
  }

  // 2b. Pre-fetched project vars (from scan's batch sibling fetch). Avoids
  //     the two-request list+decrypt round-trip when the caller already has
  //     the decrypted env map in hand.
  const vercelConsumer = secret.consumers.find((c) => c.type === "vercel-env");
  if (opts?.preFetchedVars && vercelConsumer?.params.var_name) {
    const v = opts.preFetchedVars[vercelConsumer.params.var_name];
    if (typeof v === "string" && v.length > 0) {
      return { value: v, source: "vercel-api" };
    }
  }

  // 3. Pull from Vercel. Only try the first vercel-env consumer; if the user
  //    has multiple Vercel projects with the same var they almost certainly
  //    hold the same value, and racing N requests for the same answer is
  //    wasteful.
  if (vercelConsumer) {
    try {
      const pulled = await pullFromVercel(
        vercelConsumer.params.project!,
        vercelConsumer.params.var_name!,
        vercelConsumer.params.team,
      );
      if (pulled) return { value: pulled, source: "vercel-api" };
    } catch (cause) {
      return { value: null, source: "error", error: String(cause) };
    }
  }

  return { value: null, source: "unavailable" };
}

const VERCEL_BASE = process.env.VERCEL_API_URL ?? "https://api.vercel.com";

async function pullFromVercel(
  projectId: string,
  varName: string,
  teamId?: string,
): Promise<string | null> {
  const token = resolveVercelToken();
  if (!token) return null;

  const teamQs = teamId ? `&teamId=${encodeURIComponent(teamId)}` : "";

  // Step 1: list env vars to find the id that matches varName.
  const listRes = await fetch(
    `${VERCEL_BASE}/v9/projects/${encodeURIComponent(projectId)}/env?decrypt=false${teamQs}`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  if (!listRes.ok) {
    throw new Error(`vercel list env failed: ${listRes.status}`);
  }
  const listBody = (await listRes.json()) as {
    envs?: Array<{ id: string; key: string; type: string }>;
  };
  const match = listBody.envs?.find((e) => e.key === varName);
  if (!match) return null;
  // `sensitive` vars cannot be decrypted via API — return null so the caller
  // degrades to "unknown".
  if (match.type === "sensitive" || match.type === "secret") return null;

  // Step 2: decrypt fetch.
  const decryptRes = await fetch(
    `${VERCEL_BASE}/v1/projects/${encodeURIComponent(projectId)}/env/${encodeURIComponent(match.id)}?decrypt=true${teamQs}`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  if (!decryptRes.ok) {
    throw new Error(`vercel decrypt env failed: ${decryptRes.status}`);
  }
  const decryptBody = (await decryptRes.json()) as { value?: string };
  return decryptBody.value ?? null;
}

function resolveVercelToken(): string | null {
  if (process.env.VERCEL_TOKEN) return process.env.VERCEL_TOKEN;
  // Fallback to the CLI's auth.json.
  const paths =
    platform() === "darwin"
      ? [
          join(homedir(), "Library", "Application Support", "com.vercel.cli", "auth.json"),
          join(homedir(), ".local", "share", "com.vercel.cli", "auth.json"),
        ]
      : [
          join(homedir(), ".local", "share", "com.vercel.cli", "auth.json"),
          join(homedir(), ".config", "vercel", "auth.json"),
        ];
  for (const p of paths) {
    if (!existsSync(p)) continue;
    try {
      const t = JSON.parse(readFileSync(p, "utf8")).token;
      if (typeof t === "string" && t.length > 0) return t;
    } catch {
      /* keep trying */
    }
  }
  return null;
}
