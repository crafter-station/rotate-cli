import { makeError } from "@rotate/core";
import type {
  Adapter,
  AdapterError,
  AuthContext,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const TURSO_API_BASE = process.env.TURSO_API_URL ?? "https://api.turso.tech";

interface TursoTokenResponse {
  jwt?: string;
}

export const tursoAdapter: Adapter = {
  name: "turso",

  async auth(): Promise<AuthContext> {
    const envToken = process.env.TURSO_PLATFORM_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "TURSO_PLATFORM_TOKEN", token: envToken };
    }
    throw new Error(
      "turso auth unavailable: set TURSO_PLATFORM_TOKEN to a Turso Platform API token",
    );
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const validation = validateMetadata(spec.metadata);
    if (validation.error) return { ok: false, error: validation.error };

    const { authorization, database, expiration, organization } = validation.metadata;
    const basePath = `${TURSO_API_BASE}/v1/organizations/${encodeURIComponent(
      organization,
    )}/databases/${encodeURIComponent(database)}/auth`;
    const rotateRes = await request(`${basePath}/rotate`, {
      method: "POST",
      headers: authHeaders(ctx.token),
    });
    if (rotateRes instanceof Error) return { ok: false, error: networkError(rotateRes) };
    if (!rotateRes.ok) return { ok: false, error: fromResponse(rotateRes, "create") };

    const tokenUrl = new URL(`${basePath}/tokens`);
    tokenUrl.searchParams.set("expiration", expiration);
    tokenUrl.searchParams.set("authorization", authorization);
    const tokenRes = await request(tokenUrl.toString(), {
      method: "POST",
      headers: authHeaders(ctx.token),
    });
    if (tokenRes instanceof Error) return { ok: false, error: networkError(tokenRes) };
    if (!tokenRes.ok) return { ok: false, error: fromResponse(tokenRes, "create") };

    const data = (await tokenRes.json()) as TursoTokenResponse;
    if (!data.jwt) {
      return {
        ok: false,
        error: makeError("provider_error", "turso create: response missing jwt", "turso", {
          retryable: false,
        }),
      };
    }

    const metadata = compactMetadata({
      organization,
      database,
      expiration,
      authorization,
      hostname: spec.metadata.hostname,
    });

    return {
      ok: true,
      data: {
        id: spec.secretId,
        provider: "turso",
        value: data.jwt,
        metadata,
        createdAt: new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const organization = secret.metadata.organization;
    const database = secret.metadata.database;
    if (!organization || !database) {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "metadata.organization and metadata.database are required",
          "turso",
        ),
      };
    }

    const hostname = secret.metadata.hostname ?? `${database}-${organization}.turso.io`;
    const res = await request(`https://${hostname}/v2/pipeline`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${secret.value}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        requests: [{ type: "execute", stmt: { sql: "select 1" } }],
      }),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(_secret: Secret, _ctx: AuthContext): Promise<RotationResult<void>> {
    return { ok: true, data: undefined };
  },
};

export default tursoAdapter;

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

function validateMetadata(metadata: Record<string, string>):
  | {
      metadata: {
        authorization: string;
        database: string;
        expiration: string;
        organization: string;
      };
      error?: never;
    }
  | {
      metadata?: never;
      error: AdapterError;
    } {
  const organization = metadata.organization;
  const database = metadata.database;
  if (!organization || !database) {
    return {
      error: makeError(
        "invalid_spec",
        "metadata.organization and metadata.database are required",
        "turso",
      ),
    };
  }
  return {
    metadata: {
      organization,
      database,
      expiration: metadata.expiration ?? "never",
      authorization: metadata.authorization ?? "full-access",
    },
  };
}

function compactMetadata(input: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(input).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

function networkError(cause: Error) {
  return makeError("network_error", `turso network error: ${cause.message}`, "turso", { cause });
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `turso ${op}: ${res.status}`, "turso");
  }
  if (res.status === 429) return makeError("rate_limited", `turso ${op}: 429`, "turso");
  if (res.status === 404) return makeError("not_found", `turso ${op}: 404`, "turso");
  if (res.status >= 500) {
    return makeError("provider_error", `turso ${op}: ${res.status}`, "turso");
  }
  return makeError("provider_error", `turso ${op}: ${res.status}`, "turso", {
    retryable: false,
  });
}
