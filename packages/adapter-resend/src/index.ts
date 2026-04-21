import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const RESEND_API_KEYS_BASE = process.env.RESEND_API_KEYS_URL ?? "https://api.resend.com/api-keys";
const RESEND_PROVIDER = "resend";

interface ResendCreateApiKeyResponse {
  id?: string;
  token?: string;
}

interface ResendApiKeyEntry {
  id?: string;
  name?: string;
  created_at?: string;
  last_used_at?: string | null;
}

interface ResendListApiKeysResponse {
  data?: ResendApiKeyEntry[];
}

export const resendAdapter: Adapter = {
  name: RESEND_PROVIDER,

  async auth(): Promise<AuthContext> {
    const envToken = process.env.RESEND_API_KEY;
    if (envToken) {
      return { kind: "env", varName: "RESEND_API_KEY", token: envToken };
    }
    throw new Error("resend auth unavailable: set RESEND_API_KEY");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const permission = spec.metadata.permission;
    if (permission && permission !== "full_access" && permission !== "sending_access") {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "metadata.permission must be full_access or sending_access",
          RESEND_PROVIDER,
        ),
      };
    }

    const name = apiKeyName(spec);
    const body: Record<string, string> = { name };
    if (permission) body.permission = permission;

    const res = await request(RESEND_API_KEYS_BASE, {
      method: "POST",
      headers: authHeaders(ctx.token),
      body: JSON.stringify(body),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };

    const data = (await res.json()) as ResendCreateApiKeyResponse;
    if (!data.id || !data.token) {
      return {
        ok: false,
        error: makeError(
          "provider_error",
          "resend create: missing id or token in response",
          RESEND_PROVIDER,
          { retryable: false },
        ),
      };
    }

    return {
      ok: true,
      data: {
        id: data.id,
        provider: RESEND_PROVIDER,
        value: data.token,
        metadata: metadataFor({
          key_id: data.id,
          name,
          permission,
        }),
        createdAt: new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const res = await request(RESEND_API_KEYS_BASE, {
      headers: authHeaders(secret.value),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const keyId = secret.metadata.key_id ?? secret.id;
    const res = await request(`${RESEND_API_KEYS_BASE}/${keyId}`, {
      method: "DELETE",
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(_filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const res = await request(RESEND_API_KEYS_BASE, {
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };

    const body = (await res.json()) as ResendListApiKeysResponse;
    return {
      ok: true,
      data: (body.data ?? []).flatMap((key) => {
        if (!key.id) return [];
        return [
          {
            id: key.id,
            provider: RESEND_PROVIDER,
            value: "<redacted>",
            metadata: metadataFor({
              key_id: key.id,
              name: key.name,
              last_used_at: key.last_used_at ?? undefined,
            }),
            createdAt: key.created_at ?? new Date(0).toISOString(),
          },
        ];
      }),
    };
  },
};

export default resendAdapter;

function authHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    "User-Agent": "rotate-cli/0.0.1",
  };
}

async function request(url: string, init: RequestInit): Promise<Response | Error> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
  }
}

function apiKeyName(spec: RotationSpec): string {
  const name = spec.metadata.name || `rotate-cli-${spec.secretId}-${Date.now()}`;
  return name.slice(0, 50);
}

function metadataFor(input: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(input).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

function networkError(cause: Error) {
  return makeError("network_error", `resend network error: ${cause.message}`, RESEND_PROVIDER, {
    cause,
  });
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `resend ${op}: ${res.status}`, RESEND_PROVIDER);
  }
  if (res.status === 429) return makeError("rate_limited", `resend ${op}: 429`, RESEND_PROVIDER);
  if (res.status === 404) return makeError("not_found", `resend ${op}: 404`, RESEND_PROVIDER);
  if (res.status >= 500) {
    return makeError("provider_error", `resend ${op}: ${res.status}`, RESEND_PROVIDER);
  }
  return makeError("provider_error", `resend ${op}: ${res.status}`, RESEND_PROVIDER, {
    retryable: false,
  });
}
