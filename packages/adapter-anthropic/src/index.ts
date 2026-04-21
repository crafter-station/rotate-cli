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

const ANTHROPIC_BASE = process.env.ANTHROPIC_API_URL ?? "https://api.anthropic.com";
const API_KEYS_PATH = "/v1/organizations/api_keys";
const ANTHROPIC_VERSION = "2023-06-01";

interface AnthropicApiKey {
  id?: string;
  name?: string;
  api_key?: string;
  key?: string;
  secret?: string;
  value?: string;
  partial_key?: string;
  created_at?: string;
  createdAt?: string;
  workspace_id?: string;
  status?: string;
}

interface AnthropicListResponse {
  data?: AnthropicApiKey[];
}

export const anthropicAdapter: Adapter = {
  name: "anthropic",

  async auth(): Promise<AuthContext> {
    for (const path of candidateAuthPaths()) {
      if (!existsSync(path)) continue;
      try {
        const data = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
        const token = firstString(data, ["admin_key", "api_key", "token", "key"]);
        if (token) {
          return { kind: "cli-piggyback", tool: "anthropic", tokenPath: path, token };
        }
      } catch {}
    }
    const envToken = process.env.ANTHROPIC_ADMIN_KEY;
    if (envToken) {
      return { kind: "env", varName: "ANTHROPIC_ADMIN_KEY", token: envToken };
    }
    throw new Error("anthropic auth unavailable: set ANTHROPIC_ADMIN_KEY");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const name = spec.metadata.name ?? `rotate-cli-${spec.secretId}-${Date.now()}`;
    const body: Record<string, string> = { name };
    if (spec.metadata.workspace_id) body.workspace_id = spec.metadata.workspace_id;

    const res = await request(`${ANTHROPIC_BASE}${API_KEYS_PATH}`, {
      method: "POST",
      headers: authHeaders(ctx.token),
      body: JSON.stringify(body),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };

    const data = (await res.json()) as AnthropicApiKey;
    const keyId = data.id;
    const value = data.api_key ?? data.key ?? data.secret ?? data.value;
    if (!keyId || !value) {
      return {
        ok: false,
        error: makeError(
          "provider_error",
          "anthropic create: missing id or secret in response",
          "anthropic",
          { retryable: false },
        ),
      };
    }

    return {
      ok: true,
      data: {
        id: keyId,
        provider: "anthropic",
        value,
        metadata: metadataFor(data, keyId),
        createdAt: data.created_at ?? data.createdAt ?? new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const res = await request(`${ANTHROPIC_BASE}${API_KEYS_PATH}?limit=1`, {
      headers: authHeaders(secret.value),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const keyId = secret.metadata.key_id ?? secret.id;
    const res = await request(`${ANTHROPIC_BASE}${API_KEYS_PATH}/${keyId}`, {
      method: "DELETE",
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const params = new URLSearchParams();
    if (filter.limit) params.set("limit", filter.limit);
    if (filter.workspace_id) params.set("workspace_id", filter.workspace_id);
    const qs = params.size > 0 ? `?${params.toString()}` : "";
    const res = await request(`${ANTHROPIC_BASE}${API_KEYS_PATH}${qs}`, {
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };
    const body = (await res.json()) as AnthropicListResponse;
    return {
      ok: true,
      data: (body.data ?? []).flatMap((key) => {
        if (!key.id) return [];
        return [
          {
            id: key.id,
            provider: "anthropic",
            value: "<redacted>",
            metadata: metadataFor(key, key.id),
            createdAt: key.created_at ?? key.createdAt ?? new Date(0).toISOString(),
          },
        ];
      }),
    };
  },
};

export default anthropicAdapter;

function authHeaders(token: string): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "anthropic-version": ANTHROPIC_VERSION,
    "x-api-key": token,
  };
}

async function request(url: string, init: RequestInit): Promise<Response | Error> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
  }
}

function candidateAuthPaths(): string[] {
  const home = homedir();
  return [
    join(home, ".anthropic", "auth.json"),
    join(home, ".anthropic", "credentials.json"),
    join(home, ".config", "anthropic", "auth.json"),
    join(home, ".config", "anthropic", "credentials.json"),
  ];
}

function firstString(data: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = data[key];
    if (typeof value === "string" && value.length > 0) return value;
  }
  return undefined;
}

function metadataFor(data: AnthropicApiKey, keyId: string): Record<string, string> {
  const metadata: Record<string, string> = { key_id: keyId };
  if (data.name) metadata.name = data.name;
  if (data.partial_key) metadata.partial_key = data.partial_key;
  if (data.workspace_id) metadata.workspace_id = data.workspace_id;
  if (data.status) metadata.status = data.status;
  return metadata;
}

function networkError(cause: Error) {
  return makeError("network_error", `anthropic network error: ${cause.message}`, "anthropic", {
    cause,
  });
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `anthropic ${op}: ${res.status}`, "anthropic");
  }
  if (res.status === 429) return makeError("rate_limited", `anthropic ${op}: 429`, "anthropic");
  if (res.status === 404) return makeError("not_found", `anthropic ${op}: 404`, "anthropic");
  if (res.status >= 500) {
    return makeError("provider_error", `anthropic ${op}: ${res.status}`, "anthropic");
  }
  return makeError("provider_error", `anthropic ${op}: ${res.status}`, "anthropic", {
    retryable: false,
  });
}
