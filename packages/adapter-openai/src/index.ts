import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const OPENAI_ADMIN_KEYS_BASE =
  process.env.OPENAI_ADMIN_KEYS_URL ?? "https://api.openai.com/v1/organization/admin_api_keys";

interface OpenAIAdminApiKey {
  id: string;
  name: string;
  redacted_value?: string;
  value?: string;
  created_at: number;
  last_used_at?: number | null;
  owner?: {
    id?: string;
    name?: string;
    role?: string;
    type?: string;
  };
}

interface OpenAIListResponse {
  data?: OpenAIAdminApiKey[];
}

export const openaiAdapter: Adapter = {
  name: "openai",

  async auth(): Promise<AuthContext> {
    const envToken = process.env.OPENAI_ADMIN_KEY;
    if (envToken) {
      return { kind: "env", varName: "OPENAI_ADMIN_KEY", token: envToken };
    }
    throw new Error("openai auth unavailable: set OPENAI_ADMIN_KEY to an OpenAI admin API key");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const name = spec.metadata.name ?? `rotate-cli-${spec.secretId}-${Date.now()}`;
    const res = await request(`${OPENAI_ADMIN_KEYS_BASE}`, {
      method: "POST",
      headers: authHeaders(ctx.token),
      body: JSON.stringify({ name }),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };
    const data = (await res.json()) as OpenAIAdminApiKey;
    if (!data.value) {
      return {
        ok: false,
        error: makeError("provider_error", "openai create: response missing key value", "openai", {
          retryable: false,
        }),
      };
    }
    return {
      ok: true,
      data: {
        id: data.id,
        provider: "openai",
        value: data.value,
        metadata: compactMetadata({
          key_id: data.id,
          name: data.name,
          redacted_value: data.redacted_value,
          owner_id: data.owner?.id,
          owner_name: data.owner?.name,
          owner_role: data.owner?.role,
        }),
        createdAt: new Date(data.created_at * 1000).toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const res = await request(`${OPENAI_ADMIN_KEYS_BASE}?limit=1`, {
      headers: authHeaders(secret.value),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const keyId = secret.metadata.key_id ?? secret.id;
    const res = await request(`${OPENAI_ADMIN_KEYS_BASE}/${keyId}`, {
      method: "DELETE",
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const limit = filter.limit ?? "20";
    const after = filter.after ? `&after=${encodeURIComponent(filter.after)}` : "";
    const order = filter.order ? `&order=${encodeURIComponent(filter.order)}` : "";
    const res = await request(
      `${OPENAI_ADMIN_KEYS_BASE}?limit=${encodeURIComponent(limit)}${after}${order}`,
      {
        headers: authHeaders(ctx.token),
      },
    );
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };
    const body = (await res.json()) as OpenAIListResponse;
    return {
      ok: true,
      data: (body.data ?? []).map((key) => ({
        id: key.id,
        provider: "openai",
        value: "<redacted>",
        metadata: compactMetadata({
          key_id: key.id,
          name: key.name,
          redacted_value: key.redacted_value,
          owner_id: key.owner?.id,
          owner_name: key.owner?.name,
          owner_role: key.owner?.role,
        }),
        createdAt: new Date(key.created_at * 1000).toISOString(),
      })),
    };
  },
};

export default openaiAdapter;

function authHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

async function request(url: string, init: RequestInit): Promise<Response | Error> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
  }
}

function compactMetadata(input: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(input).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

function networkError(cause: Error) {
  return makeError("network_error", `openai network error: ${cause.message}`, "openai", { cause });
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `openai ${op}: ${res.status}`, "openai");
  }
  if (res.status === 429) return makeError("rate_limited", `openai ${op}: 429`, "openai");
  if (res.status === 404) return makeError("not_found", `openai ${op}: 404`, "openai");
  if (res.status >= 500) {
    return makeError("provider_error", `openai ${op}: ${res.status}`, "openai");
  }
  return makeError("provider_error", `openai ${op}: ${res.status}`, "openai", {
    retryable: false,
  });
}
