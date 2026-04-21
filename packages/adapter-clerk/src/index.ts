/**
 * @rotate/adapter-clerk — Clerk secret key rotation.
 *
 * Auth: CLI piggyback. Reads Clerk CLI auth token.
 *   Expected file: ~/.clerk/auth.json  { "token": "plapi_live_..." }
 *   Fallback env var: CLERK_PLAPI_TOKEN
 *
 * Operations:
 *   - create: POST PLAPI /v1/instances/{instance_id}/api_keys
 *   - verify: GET  PLAPI /v1/me  (must succeed with the NEW key to return ok)
 *   - revoke: DELETE PLAPI /v1/instances/{instance_id}/api_keys/{key_id}
 *   - list:   GET    PLAPI /v1/instances/{instance_id}/api_keys
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const PLAPI_BASE = process.env.CLERK_PLAPI_URL ?? "https://api.clerk.com";

export interface ClerkApiKey {
  id: string;
  secret: string;
  instance_id: string;
  created_at: number;
}

export const clerkAdapter: Adapter = {
  name: "clerk",

  async auth(): Promise<AuthContext> {
    const envToken = process.env.CLERK_PLAPI_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "CLERK_PLAPI_TOKEN", token: envToken };
    }
    const path = join(homedir(), ".clerk", "auth.json");
    if (existsSync(path)) {
      try {
        const data = JSON.parse(readFileSync(path, "utf8")) as { token?: string };
        if (data.token) {
          return { kind: "cli-piggyback", tool: "clerk", tokenPath: path, token: data.token };
        }
      } catch {
        /* fallthrough */
      }
    }
    throw new Error("clerk auth unavailable: run `clerk login` or set CLERK_PLAPI_TOKEN");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const instanceId = spec.metadata.instance_id;
    if (!instanceId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.instance_id is required", "clerk"),
      };
    }
    const res = await fetch(`${PLAPI_BASE}/v1/instances/${instanceId}/api_keys`, {
      method: "POST",
      headers: authHeaders(ctx),
      body: JSON.stringify({ name: `rotate-cli-${Date.now()}` }),
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };
    const data = (await res.json()) as ClerkApiKey;
    return {
      ok: true,
      data: {
        id: data.id,
        provider: "clerk",
        value: data.secret,
        metadata: { instance_id: data.instance_id, key_id: data.id },
        createdAt: new Date((data.created_at ?? Date.now()) * 1000).toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    // Verify the NEW key by calling /v1/me with it as bearer.
    const res = await fetch(`${PLAPI_BASE}/v1/me`, {
      headers: { Authorization: `Bearer ${secret.value}` },
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const instanceId = secret.metadata.instance_id;
    const keyId = secret.metadata.key_id ?? secret.id;
    if (!instanceId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.instance_id missing", "clerk"),
      };
    }
    const res = await fetch(`${PLAPI_BASE}/v1/instances/${instanceId}/api_keys/${keyId}`, {
      method: "DELETE",
      headers: authHeaders(ctx),
    });
    if (res.status === 404) return { ok: true, data: undefined }; // idempotent
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const instanceId = filter.instance_id;
    if (!instanceId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "filter.instance_id required", "clerk"),
      };
    }
    const res = await fetch(`${PLAPI_BASE}/v1/instances/${instanceId}/api_keys`, {
      headers: authHeaders(ctx),
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };
    const data = (await res.json()) as ClerkApiKey[];
    return {
      ok: true,
      data: data.map((k) => ({
        id: k.id,
        provider: "clerk",
        value: "<redacted>",
        metadata: { instance_id: k.instance_id, key_id: k.id },
        createdAt: new Date((k.created_at ?? 0) * 1000).toISOString(),
      })),
    };
  },
};

export default clerkAdapter;

function authHeaders(ctx: AuthContext): Record<string, string> {
  return {
    Authorization: `Bearer ${ctx.token}`,
    "Content-Type": "application/json",
  };
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `clerk ${op}: ${res.status}`, "clerk");
  }
  if (res.status === 429) return makeError("rate_limited", `clerk ${op}: 429`, "clerk");
  if (res.status === 404) return makeError("not_found", `clerk ${op}: 404`, "clerk");
  if (res.status >= 500) {
    return makeError("provider_error", `clerk ${op}: ${res.status}`, "clerk");
  }
  return makeError("provider_error", `clerk ${op}: ${res.status}`, "clerk", {
    retryable: false,
  });
}
