import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const UPSTASH_API_BASE = process.env.UPSTASH_API_URL ?? "https://api.upstash.com/v2";
const UPSTASH_PROVIDER = "upstash";

interface UpstashResetPasswordResponse {
  database_id?: string;
  id?: string;
  password?: string;
  rest_token?: string;
  restToken?: string;
  last_password_rotation?: string;
  lastPasswordRotation?: string;
}

interface UpstashDatabase {
  database_id?: string;
  id?: string;
  database_name?: string;
  databaseName?: string;
  region?: string;
  type?: string;
  state?: string;
  creation_time?: number;
  creationTime?: number;
  created_at?: string;
  createdAt?: string;
  rest_token?: string;
  restToken?: string;
  last_password_rotation?: string;
  lastPasswordRotation?: string;
}

export const upstashAdapter: Adapter = {
  name: UPSTASH_PROVIDER,

  async auth(): Promise<AuthContext> {
    const email = process.env.UPSTASH_EMAIL;
    const apiKey = process.env.UPSTASH_API_KEY;
    if (email && apiKey) {
      return {
        kind: "env",
        varName: "UPSTASH_EMAIL,UPSTASH_API_KEY",
        token: `${email}:${apiKey}`,
      };
    }
    throw new Error("upstash auth unavailable: set UPSTASH_EMAIL and UPSTASH_API_KEY");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const databaseId = spec.metadata.database_id;
    if (!databaseId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.database_id is required", UPSTASH_PROVIDER),
      };
    }

    const res = await request(`${UPSTASH_API_BASE}/redis/reset-password/${databaseId}`, {
      method: "POST",
      headers: authHeaders(ctx),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };

    const data = (await res.json()) as UpstashResetPasswordResponse;
    const restToken = data.rest_token ?? data.restToken;
    if (!restToken) {
      return {
        ok: false,
        error: makeError(
          "provider_error",
          "upstash create: response missing rest_token",
          UPSTASH_PROVIDER,
          { retryable: false },
        ),
      };
    }

    const rotatedAt = data.last_password_rotation ?? data.lastPasswordRotation;
    return {
      ok: true,
      data: {
        id: data.database_id ?? data.id ?? databaseId,
        provider: UPSTASH_PROVIDER,
        value: restToken,
        metadata: compactMetadata({
          database_id: data.database_id ?? data.id ?? databaseId,
          last_password_rotation: rotatedAt,
        }),
        createdAt: rotatedAt ?? new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, ctx: AuthContext): Promise<RotationResult<boolean>> {
    const databaseId = secret.metadata.database_id;
    if (!databaseId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.database_id missing", UPSTASH_PROVIDER),
      };
    }

    const email = emailFromAuth(ctx);
    if (!email) {
      return {
        ok: false,
        error: makeError(
          "auth_failed",
          "upstash verify: UPSTASH_EMAIL is required to verify REST token",
          UPSTASH_PROVIDER,
        ),
      };
    }

    const res = await request(`${UPSTASH_API_BASE}/redis/database/${databaseId}`, {
      headers: basicAuthHeaders(email, secret.value),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(_secret: Secret, _ctx: AuthContext): Promise<RotationResult<void>> {
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const res = await request(`${UPSTASH_API_BASE}/redis/databases`, {
      headers: authHeaders(ctx),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };

    const data = (await res.json()) as UpstashDatabase[];
    const databaseId = filter.database_id;
    const databases = databaseId
      ? data.filter((database) => (database.database_id ?? database.id) === databaseId)
      : data;

    return {
      ok: true,
      data: databases.flatMap((database) => {
        const id = database.database_id ?? database.id;
        if (!id) return [];
        return [
          {
            id,
            provider: UPSTASH_PROVIDER,
            value: "<redacted>",
            metadata: compactMetadata({
              database_id: id,
              name: database.database_name ?? database.databaseName,
              region: database.region,
              type: database.type,
              state: database.state,
              last_password_rotation:
                database.last_password_rotation ?? database.lastPasswordRotation,
            }),
            createdAt: createdAtFor(database),
          },
        ];
      }),
    };
  },
};

export default upstashAdapter;

function authHeaders(ctx: AuthContext): Record<string, string> {
  const [email, apiKey] = splitAuthToken(ctx.token);
  return basicAuthHeaders(email, apiKey);
}

function basicAuthHeaders(email: string, password: string): Record<string, string> {
  return {
    Authorization: `Basic ${Buffer.from(`${email}:${password}`).toString("base64")}`,
    "Content-Type": "application/json",
  };
}

function emailFromAuth(ctx: AuthContext): string | undefined {
  return splitAuthToken(ctx.token)[0] || undefined;
}

function splitAuthToken(token: string): [string, string] {
  const separator = token.indexOf(":");
  if (separator === -1) return ["", token];
  return [token.slice(0, separator), token.slice(separator + 1)];
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

function createdAtFor(database: UpstashDatabase): string {
  if (database.created_at) return database.created_at;
  if (database.createdAt) return database.createdAt;
  const timestamp = database.creation_time ?? database.creationTime;
  if (timestamp !== undefined) return new Date(timestamp).toISOString();
  return new Date(0).toISOString();
}

function networkError(cause: Error) {
  return makeError("network_error", `upstash network error: ${cause.message}`, UPSTASH_PROVIDER, {
    cause,
  });
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `upstash ${op}: ${res.status}`, UPSTASH_PROVIDER);
  }
  if (res.status === 429) {
    return makeError("rate_limited", `upstash ${op}: 429`, UPSTASH_PROVIDER);
  }
  if (res.status === 404) {
    return makeError("not_found", `upstash ${op}: 404`, UPSTASH_PROVIDER);
  }
  if (res.status >= 500) {
    return makeError("provider_error", `upstash ${op}: ${res.status}`, UPSTASH_PROVIDER);
  }
  return makeError("provider_error", `upstash ${op}: ${res.status}`, UPSTASH_PROVIDER, {
    retryable: false,
  });
}
