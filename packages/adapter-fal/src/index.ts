import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const FAL_API_BASE = process.env.FAL_API_URL ?? "https://api.fal.ai/v1";
const FAL_PROVIDER = "fal-ai";

interface FalCreateKeyResponse {
  key_id?: string;
  key_secret?: string;
  key?: string;
}

interface FalKeyEntry {
  key_id?: string;
  alias?: string;
  scope?: string;
  created_at?: string;
  creator_nickname?: string;
  creator_email?: string;
}

interface FalListKeysResponse {
  next_cursor?: string;
  has_more?: boolean;
  keys?: FalKeyEntry[];
}

export const falAdapter: Adapter = {
  name: FAL_PROVIDER,

  async auth(): Promise<AuthContext> {
    const envToken = process.env.FAL_ADMIN_KEY;
    if (envToken) {
      return { kind: "env", varName: "FAL_ADMIN_KEY", token: envToken };
    }
    throw new Error("fal.ai auth unavailable: set FAL_ADMIN_KEY to an ADMIN-scoped key");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const alias = keyAlias(spec);
    const res = await request(`${FAL_API_BASE}/keys`, {
      method: "POST",
      headers: authHeaders(ctx.token),
      body: JSON.stringify({ alias }),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };

    const data = (await res.json()) as FalCreateKeyResponse;
    if (!data.key_id || !data.key) {
      return {
        ok: false,
        error: makeError(
          "provider_error",
          "fal-ai create: response missing key_id or key",
          FAL_PROVIDER,
          { retryable: false },
        ),
      };
    }

    const createdAt = await createdAtForKey(data.key_id, ctx.token);

    return {
      ok: true,
      data: {
        id: data.key_id,
        provider: FAL_PROVIDER,
        value: data.key,
        metadata: compactMetadata({
          key_id: data.key_id,
          alias,
        }),
        createdAt,
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const res = await request(`${FAL_API_BASE}/models/usage`, {
      headers: authHeaders(secret.value),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const keyId = secret.metadata.key_id ?? secret.id;
    const res = await request(`${FAL_API_BASE}/keys/${encodeURIComponent(keyId)}`, {
      method: "DELETE",
      headers: {
        ...authHeaders(ctx.token),
        "Idempotency-Key": crypto.randomUUID(),
      },
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const keys = await listKeys(ctx.token, filter);
    if (keys instanceof Error) return { ok: false, error: networkError(keys) };
    if (keys instanceof Response) return { ok: false, error: fromResponse(keys, "list") };

    return {
      ok: true,
      data: keys.map((key) => ({
        id: key.key_id ?? "",
        provider: FAL_PROVIDER,
        value: "<redacted>",
        metadata: compactMetadata({
          key_id: key.key_id,
          alias: key.alias,
          scope: key.scope,
          creator_nickname: key.creator_nickname,
          creator_email: key.creator_email,
        }),
        createdAt: key.created_at ?? new Date(0).toISOString(),
      })),
    };
  },
};

export default falAdapter;

function authHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Key ${token}`,
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

function keyAlias(spec: RotationSpec): string {
  const alias = (spec.metadata.alias || spec.metadata.name || "").trim();
  return (alias || `rotate-cli ${new Date().toISOString()}`).slice(0, 255);
}

async function createdAtForKey(keyId: string, token: string): Promise<string> {
  const keys = await listKeys(token, { key_id: keyId, limit: "50" });
  if (Array.isArray(keys)) {
    const createdAt = keys.find((key) => key.key_id === keyId)?.created_at;
    if (createdAt) return createdAt;
  }
  return new Date().toISOString();
}

async function listKeys(
  token: string,
  filter: Record<string, string>,
): Promise<FalKeyEntry[] | Response | Error> {
  const limit = filter.limit ?? "50";
  const cursor = filter.cursor ? `&cursor=${encodeURIComponent(filter.cursor)}` : "";
  const res = await request(
    `${FAL_API_BASE}/keys?limit=${encodeURIComponent(limit)}&expand=creator_info${cursor}`,
    {
      headers: authHeaders(token),
    },
  );
  if (res instanceof Error) return res;
  if (!res.ok) return res;

  const body = (await res.json()) as FalListKeysResponse;
  const keys = body.keys ?? [];
  return keys.filter((key) => {
    if (filter.key_id && key.key_id !== filter.key_id) return false;
    if (filter.alias && key.alias !== filter.alias) return false;
    if (filter.alias_prefix && !key.alias?.startsWith(filter.alias_prefix)) return false;
    if (filter.scope && key.scope !== filter.scope) return false;
    return Boolean(key.key_id);
  });
}

function compactMetadata(input: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(input).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

function networkError(cause: Error) {
  return makeError("network_error", `fal-ai network error: ${cause.message}`, FAL_PROVIDER, {
    cause,
  });
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `fal-ai ${op}: ${res.status}`, FAL_PROVIDER);
  }
  if (res.status === 429) return makeError("rate_limited", `fal-ai ${op}: 429`, FAL_PROVIDER);
  if (res.status === 404) return makeError("not_found", `fal-ai ${op}: 404`, FAL_PROVIDER);
  if (res.status >= 500) {
    return makeError("provider_error", `fal-ai ${op}: ${res.status}`, FAL_PROVIDER);
  }
  return makeError("provider_error", `fal-ai ${op}: ${res.status}`, FAL_PROVIDER, {
    retryable: false,
  });
}
