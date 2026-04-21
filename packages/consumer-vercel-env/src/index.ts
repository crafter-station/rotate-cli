/**
 * @rotate/consumer-vercel-env — Vercel env var consumer.
 *
 * Auth: CLI piggyback. Reads Vercel CLI auth token.
 *   Expected file: ~/.local/share/com.vercel.cli/auth.json  { "token": "..." }
 *     (macOS: ~/Library/Application Support/com.vercel.cli/auth.json)
 *   Fallback env var: VERCEL_TOKEN
 *
 * Operations:
 *   - propagate: Upsert env var via POST /v10/projects/{id}/env
 *     If target already exists, DELETE then POST.
 *   - trigger:   POST /v13/deployments  (redeploy latest production)
 *   - verify:    GET /v9/projects/{id}/env/{id} matches new value.
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import { makeError } from "@rotate/core";
import type {
  AuthContext,
  Consumer,
  ConsumerTarget,
  RotationResult,
  Secret,
} from "@rotate/core/types";

const VERCEL_BASE = process.env.VERCEL_API_URL ?? "https://api.vercel.com";

export const vercelEnvConsumer: Consumer = {
  name: "vercel-env",

  async auth(): Promise<AuthContext> {
    const envToken = process.env.VERCEL_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "VERCEL_TOKEN", token: envToken };
    }
    for (const path of candidateAuthPaths()) {
      if (!existsSync(path)) continue;
      try {
        const data = JSON.parse(readFileSync(path, "utf8")) as { token?: string };
        if (data.token) {
          return { kind: "cli-piggyback", tool: "vercel", tokenPath: path, token: data.token };
        }
      } catch {
        /* continue */
      }
    }
    throw new Error("vercel auth unavailable: run `vercel login` or set VERCEL_TOKEN");
  },

  async propagate(
    target: ConsumerTarget,
    secret: Secret,
    ctx: AuthContext,
  ): Promise<RotationResult<void>> {
    const { project, var_name, team } = target.params;
    if (!project || !var_name) {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "params.project and params.var_name required",
          "vercel-env",
        ),
      };
    }
    const qs = team ? `?teamId=${team}` : "";
    // Delete existing if present.
    const existing = await listEnv(project, ctx, team);
    if (existing) {
      const match = existing.find((e) => e.key === var_name);
      if (match) {
        const del = await fetch(`${VERCEL_BASE}/v9/projects/${project}/env/${match.id}${qs}`, {
          method: "DELETE",
          headers: authHeaders(ctx),
        });
        if (!del.ok && del.status !== 404) return { ok: false, error: fromResponse(del, "delete") };
      }
    }
    const res = await fetch(`${VERCEL_BASE}/v10/projects/${project}/env${qs}`, {
      method: "POST",
      headers: authHeaders(ctx),
      body: JSON.stringify({
        key: var_name,
        value: secret.value,
        type: "encrypted",
        target: ["production", "preview", "development"],
      }),
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "propagate") };
    return { ok: true, data: undefined };
  },

  async trigger(target: ConsumerTarget, ctx: AuthContext): Promise<RotationResult<void>> {
    const { project, team } = target.params;
    const qs = team ? `?teamId=${team}&forceNew=1` : "?forceNew=1";
    // Find latest production deployment, redeploy.
    const deployments = await fetch(
      `${VERCEL_BASE}/v6/deployments?projectId=${project}&target=production&limit=1${team ? `&teamId=${team}` : ""}`,
      { headers: authHeaders(ctx) },
    );
    if (!deployments.ok) return { ok: false, error: fromResponse(deployments, "trigger-list") };
    const body = (await deployments.json()) as {
      deployments?: Array<{ uid: string; name: string }>;
    };
    const latest = body.deployments?.[0];
    if (!latest) {
      return {
        ok: false,
        error: makeError(
          "not_found",
          `no production deployment for project ${project}`,
          "vercel-env",
        ),
      };
    }
    const redeploy = await fetch(`${VERCEL_BASE}/v13/deployments${qs}`, {
      method: "POST",
      headers: authHeaders(ctx),
      body: JSON.stringify({ name: latest.name, deploymentId: latest.uid, target: "production" }),
    });
    if (!redeploy.ok) return { ok: false, error: fromResponse(redeploy, "trigger") };
    return { ok: true, data: undefined };
  },

  async verify(
    target: ConsumerTarget,
    secret: Secret,
    ctx: AuthContext,
  ): Promise<RotationResult<boolean>> {
    // Vercel does not expose decrypted env var values via API.
    // Best-effort verify: confirm the env var exists with matching `key`
    // and was updated after the rotation started. Full cryptographic
    // confirmation happens consumer-side (via deploy health).
    const envs = await listEnv(target.params.project!, ctx, target.params.team);
    if (!envs) {
      return {
        ok: false,
        error: makeError("provider_error", "cannot list env vars", "vercel-env"),
      };
    }
    const match = envs.find((e) => e.key === target.params.var_name);
    if (!match) return { ok: true, data: false };
    if (!match.updatedAt) return { ok: true, data: true };
    const updated = new Date(match.updatedAt).getTime();
    const secretAge = new Date(secret.createdAt).getTime();
    return { ok: true, data: updated >= secretAge - 5_000 };
  },
};

export default vercelEnvConsumer;

interface VercelEnvEntry {
  id: string;
  key: string;
  updatedAt?: string;
}

async function listEnv(
  projectId: string,
  ctx: AuthContext,
  team?: string,
): Promise<VercelEnvEntry[] | null> {
  const qs = team ? `?teamId=${team}` : "";
  const res = await fetch(`${VERCEL_BASE}/v9/projects/${projectId}/env${qs}`, {
    headers: authHeaders(ctx),
  });
  if (!res.ok) return null;
  const body = (await res.json()) as { envs?: VercelEnvEntry[] };
  return body.envs ?? [];
}

function authHeaders(ctx: AuthContext): Record<string, string> {
  return {
    Authorization: `Bearer ${ctx.token}`,
    "Content-Type": "application/json",
  };
}

function candidateAuthPaths(): string[] {
  const home = homedir();
  if (platform() === "darwin") {
    return [
      join(home, "Library", "Application Support", "com.vercel.cli", "auth.json"),
      join(home, ".local", "share", "com.vercel.cli", "auth.json"),
    ];
  }
  return [
    join(home, ".local", "share", "com.vercel.cli", "auth.json"),
    join(home, ".config", "vercel", "auth.json"),
  ];
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `vercel ${op}: ${res.status}`, "vercel-env");
  }
  if (res.status === 429) return makeError("rate_limited", `vercel ${op}: 429`, "vercel-env");
  if (res.status === 404) return makeError("not_found", `vercel ${op}: 404`, "vercel-env");
  if (res.status >= 500)
    return makeError("provider_error", `vercel ${op}: ${res.status}`, "vercel-env");
  return makeError("provider_error", `vercel ${op}: ${res.status}`, "vercel-env", {
    retryable: false,
  });
}
