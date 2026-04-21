import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const NEON_BASE = process.env.NEON_API_URL ?? "https://console.neon.tech/api/v2";

interface NeonApiKey {
  id: string | number;
  key: string;
  created_at?: string | number;
  project_id?: string;
}

export const neonAdapter: Adapter = {
  name: "neon",

  async auth(): Promise<AuthContext> {
    const envToken = process.env.NEON_API_KEY;
    if (envToken) {
      return { kind: "env", varName: "NEON_API_KEY", token: envToken };
    }
    throw new Error("neon auth unavailable: set NEON_API_KEY");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const projectId = spec.metadata.project_id;
    if (!projectId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.project_id is required", "neon"),
      };
    }
    const res = await fetch(`${NEON_BASE}/projects/${projectId}/api_keys`, {
      method: "POST",
      headers: authHeaders(ctx),
      body: JSON.stringify({ key_name: `rotate-cli-${Date.now()}` }),
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };
    const data = (await res.json()) as NeonApiKey;
    const keyId = String(data.id);
    return {
      ok: true,
      data: {
        id: keyId,
        provider: "neon",
        value: data.key,
        metadata: { project_id: data.project_id ?? projectId, key_id: keyId },
        createdAt: parseCreatedAt(data.created_at),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const res = await fetch(`${NEON_BASE}/users/me`, {
      headers: { Authorization: `Bearer ${secret.value}` },
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const projectId = secret.metadata.project_id;
    const keyId = secret.metadata.key_id ?? secret.id;
    if (!projectId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.project_id missing", "neon"),
      };
    }
    const res = await fetch(`${NEON_BASE}/projects/${projectId}/api_keys/${keyId}`, {
      method: "DELETE",
      headers: authHeaders(ctx),
    });
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },
};

export default neonAdapter;

function authHeaders(ctx: AuthContext): Record<string, string> {
  return {
    Authorization: `Bearer ${ctx.token}`,
    "Content-Type": "application/json",
  };
}

function parseCreatedAt(value: string | number | undefined): string {
  if (typeof value === "number") {
    return new Date(value > 999_999_999_999 ? value : value * 1000).toISOString();
  }
  if (value) {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  }
  return new Date().toISOString();
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `neon ${op}: ${res.status}`, "neon");
  }
  if (res.status === 429) return makeError("rate_limited", `neon ${op}: 429`, "neon");
  if (res.status === 404) return makeError("not_found", `neon ${op}: 404`, "neon");
  if (res.status >= 500) {
    return makeError("provider_error", `neon ${op}: ${res.status}`, "neon");
  }
  return makeError("provider_error", `neon ${op}: ${res.status}`, "neon", {
    retryable: false,
  });
}
