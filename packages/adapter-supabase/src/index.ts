import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const SUPABASE_API_BASE = process.env.SUPABASE_API_URL ?? "https://api.supabase.com";
const SUPABASE_PROJECT_BASE =
  process.env.SUPABASE_PROJECT_URL_BASE ?? "https://{project_ref}.supabase.co";

interface SupabaseApiKey {
  api_key?: string;
  id: string;
  type?: string;
  prefix?: string;
  name?: string;
  description?: string;
  hash?: string;
  inserted_at?: string;
  updated_at?: string;
}

export const supabaseAdapter: Adapter = {
  name: "supabase",

  async auth(): Promise<AuthContext> {
    const envToken = process.env.SUPABASE_ACCESS_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "SUPABASE_ACCESS_TOKEN", token: envToken };
    }
    throw new Error("supabase auth unavailable: set SUPABASE_ACCESS_TOKEN");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const projectRef = spec.metadata.project_ref;
    if (!projectRef) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.project_ref is required", "supabase"),
      };
    }

    const keyType = spec.metadata.type ?? "secret";
    const name = spec.metadata.name ?? `rotate-cli-${Date.now()}`;
    const body: Record<string, string> = { type: keyType, name };
    if (spec.reason) body.description = spec.reason;

    const res = await fetch(`${SUPABASE_API_BASE}/v1/projects/${projectRef}/api-keys?reveal=true`, {
      method: "POST",
      headers: authHeaders(ctx),
      body: JSON.stringify(body),
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };

    const data = (await res.json()) as SupabaseApiKey;
    if (!data.api_key) {
      return {
        ok: false,
        error: makeError(
          "provider_error",
          "supabase create: response did not include api_key",
          "supabase",
          { retryable: false },
        ),
      };
    }

    return {
      ok: true,
      data: {
        id: data.id,
        provider: "supabase",
        value: data.api_key,
        metadata: compactMetadata({
          project_ref: projectRef,
          key_id: data.id,
          type: data.type ?? keyType,
          name: data.name ?? name,
          prefix: data.prefix,
        }),
        createdAt: data.inserted_at ?? new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const projectRef = secret.metadata.project_ref;
    if (!projectRef) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.project_ref missing", "supabase"),
      };
    }

    const projectUrl = secret.metadata.project_url ?? projectApiUrl(projectRef);
    const res = await fetch(`${projectUrl}/rest/v1/`, {
      headers: {
        apikey: secret.value,
      },
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const projectRef = secret.metadata.project_ref;
    const keyId = secret.metadata.key_id ?? secret.id;
    if (!projectRef) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.project_ref missing", "supabase"),
      };
    }

    const res = await fetch(`${SUPABASE_API_BASE}/v1/projects/${projectRef}/api-keys/${keyId}`, {
      method: "DELETE",
      headers: authHeaders(ctx),
    });
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const projectRef = filter.project_ref;
    if (!projectRef) {
      return {
        ok: false,
        error: makeError("invalid_spec", "filter.project_ref required", "supabase"),
      };
    }

    const res = await fetch(
      `${SUPABASE_API_BASE}/v1/projects/${projectRef}/api-keys?reveal=false`,
      {
        headers: authHeaders(ctx),
      },
    );
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };

    const data = (await res.json()) as SupabaseApiKey[];
    return {
      ok: true,
      data: data.map((key) => ({
        id: key.id,
        provider: "supabase",
        value: "<redacted>",
        metadata: compactMetadata({
          project_ref: projectRef,
          key_id: key.id,
          type: key.type,
          name: key.name,
          prefix: key.prefix,
        }),
        createdAt: key.inserted_at ?? new Date(0).toISOString(),
      })),
    };
  },
};

export default supabaseAdapter;

function authHeaders(ctx: AuthContext): Record<string, string> {
  return {
    Authorization: `Bearer ${ctx.token}`,
    "Content-Type": "application/json",
  };
}

function projectApiUrl(projectRef: string): string {
  return SUPABASE_PROJECT_BASE.replace("{project_ref}", projectRef).replace(/\/$/, "");
}

function compactMetadata(metadata: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(metadata).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `supabase ${op}: ${res.status}`, "supabase");
  }
  if (res.status === 429) return makeError("rate_limited", `supabase ${op}: 429`, "supabase");
  if (res.status === 404) return makeError("not_found", `supabase ${op}: 404`, "supabase");
  if (res.status >= 500) {
    return makeError("provider_error", `supabase ${op}: ${res.status}`, "supabase");
  }
  return makeError("provider_error", `supabase ${op}: ${res.status}`, "supabase", {
    retryable: false,
  });
}
