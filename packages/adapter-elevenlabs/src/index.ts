import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const ELEVENLABS_BASE = process.env.ELEVENLABS_API_URL ?? "https://api.elevenlabs.io";
const PROVIDER = "elevenlabs";

interface ElevenLabsCreateResponse {
  "xi-api-key"?: string;
  key_id?: string;
}

interface ElevenLabsKeyEntry {
  name?: string;
  hint?: string;
  key_id?: string;
  service_account_user_id?: string;
  created_at_unix?: number;
  is_disabled?: boolean;
  permissions?: string[] | "all";
  character_limit?: number | null;
  character_count?: number;
  hashed_xi_api_key?: string;
}

type ElevenLabsListResponse = ElevenLabsKeyEntry[] | { api_keys?: ElevenLabsKeyEntry[] };

export const elevenlabsAdapter: Adapter = {
  name: PROVIDER,

  async auth(): Promise<AuthContext> {
    const envToken = process.env.ELEVENLABS_ADMIN_KEY;
    if (envToken) {
      return { kind: "env", varName: "ELEVENLABS_ADMIN_KEY", token: envToken };
    }
    throw new Error("elevenlabs auth unavailable: set ELEVENLABS_ADMIN_KEY");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const serviceAccountUserId = spec.metadata.service_account_user_id;
    if (!serviceAccountUserId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.service_account_user_id is required", PROVIDER),
      };
    }

    const name = spec.metadata.name ?? `rotate-cli-managed-${new Date().toISOString()}`;
    const permissions = parsePermissions(spec.metadata.permissions);
    if (!permissions) {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "metadata.permissions must be all, a JSON string array, or a comma-separated list",
          PROVIDER,
        ),
      };
    }

    const characterLimit = parseOptionalPositiveInteger(spec.metadata.character_limit);
    if (spec.metadata.character_limit && characterLimit === undefined) {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "metadata.character_limit must be a positive integer",
          PROVIDER,
        ),
      };
    }

    const body: { name: string; permissions: string[] | "all"; character_limit?: number } = {
      name,
      permissions,
    };
    if (characterLimit !== undefined) body.character_limit = characterLimit;

    const res = await request(`${apiKeysUrl(serviceAccountUserId)}`, {
      method: "POST",
      headers: authHeaders(ctx.token),
      body: JSON.stringify(body),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };

    const data = (await res.json()) as ElevenLabsCreateResponse;
    if (!data["xi-api-key"] || !data.key_id) {
      return {
        ok: false,
        error: makeError(
          "provider_error",
          "elevenlabs create: response missing xi-api-key or key_id",
          PROVIDER,
          { retryable: false },
        ),
      };
    }

    const rotatedAt = new Date().toISOString();
    return {
      ok: true,
      data: {
        id: data.key_id,
        provider: PROVIDER,
        value: data["xi-api-key"],
        metadata: metadataFor({
          provider: PROVIDER,
          mode: "api",
          service_account_user_id: serviceAccountUserId,
          key_id: data.key_id,
          name,
          permissions: stringifyPermissions(permissions),
          character_limit: characterLimit === undefined ? undefined : String(characterLimit),
          rotated_at: rotatedAt,
          previous_key_id: spec.metadata.previous_key_id,
        }),
        createdAt: rotatedAt,
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const res = await request(`${ELEVENLABS_BASE}/v1/user`, {
      headers: authHeaders(secret.value),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const serviceAccountUserId = secret.metadata.service_account_user_id;
    const keyId = secret.metadata.key_id ?? secret.id;
    if (!serviceAccountUserId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.service_account_user_id missing", PROVIDER),
      };
    }

    const res = await request(`${apiKeysUrl(serviceAccountUserId)}/${keyId}`, {
      method: "DELETE",
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const serviceAccountUserId = filter.service_account_user_id;
    if (!serviceAccountUserId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "filter.service_account_user_id required", PROVIDER),
      };
    }

    const res = await request(apiKeysUrl(serviceAccountUserId), {
      headers: authHeaders(ctx.token),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };

    const body = (await res.json()) as ElevenLabsListResponse;
    const keys = Array.isArray(body) ? body : (body.api_keys ?? []);
    return {
      ok: true,
      data: keys.flatMap((key) => {
        if (!key.key_id) return [];
        const createdAt = key.created_at_unix
          ? new Date(key.created_at_unix * 1000).toISOString()
          : new Date(0).toISOString();
        return [
          {
            id: key.key_id,
            provider: PROVIDER,
            value: "<redacted>",
            metadata: metadataFor({
              provider: PROVIDER,
              mode: "api",
              service_account_user_id: key.service_account_user_id ?? serviceAccountUserId,
              key_id: key.key_id,
              name: key.name,
              permissions:
                key.permissions === undefined ? undefined : stringifyPermissions(key.permissions),
              character_limit:
                key.character_limit === undefined || key.character_limit === null
                  ? undefined
                  : String(key.character_limit),
              hint: key.hint,
              created_at_unix:
                key.created_at_unix === undefined ? undefined : String(key.created_at_unix),
              is_disabled: key.is_disabled === undefined ? undefined : String(key.is_disabled),
              character_count:
                key.character_count === undefined ? undefined : String(key.character_count),
              hashed_xi_api_key: key.hashed_xi_api_key,
            }),
            createdAt,
          },
        ];
      }),
    };
  },
};

export default elevenlabsAdapter;

function apiKeysUrl(serviceAccountUserId: string): string {
  return `${ELEVENLABS_BASE}/v1/service-accounts/${serviceAccountUserId}/api-keys`;
}

function authHeaders(token: string): Record<string, string> {
  return {
    "xi-api-key": token,
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

function parsePermissions(value: string | undefined): string[] | "all" | undefined {
  if (!value || value === "all") return "all";
  if (value.trim().startsWith("[")) {
    try {
      const parsed = JSON.parse(value) as unknown;
      if (Array.isArray(parsed) && parsed.every((item) => typeof item === "string")) {
        return parsed;
      }
      return undefined;
    } catch {
      return undefined;
    }
  }
  const permissions = value
    .split(",")
    .map((permission) => permission.trim())
    .filter(Boolean);
  return permissions.length > 0 ? permissions : undefined;
}

function parseOptionalPositiveInteger(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) return undefined;
  return parsed;
}

function stringifyPermissions(value: string[] | "all"): string {
  return value === "all" ? "all" : JSON.stringify(value);
}

function metadataFor(input: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(input).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

function networkError(cause: Error) {
  return makeError("network_error", `elevenlabs network error: ${cause.message}`, PROVIDER, {
    cause,
  });
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401) {
    return makeError("auth_failed", `elevenlabs ${op}: 401`, PROVIDER);
  }
  if (res.status === 403) {
    return makeError(
      "auth_failed",
      `elevenlabs ${op}: 403; service-account key management requires a multi-seat workspace`,
      PROVIDER,
    );
  }
  if (res.status === 429) return makeError("rate_limited", `elevenlabs ${op}: 429`, PROVIDER);
  if (res.status === 404) return makeError("not_found", `elevenlabs ${op}: 404`, PROVIDER);
  if (res.status >= 500) {
    return makeError("provider_error", `elevenlabs ${op}: ${res.status}`, PROVIDER);
  }
  return makeError("provider_error", `elevenlabs ${op}: ${res.status}`, PROVIDER, {
    retryable: false,
  });
}
