import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const NEON_BASE = process.env.NEON_API_URL ?? "https://console.neon.tech/api/v2";
const DEFAULT_BRANCH_ID = "main";

interface NeonResetPasswordResponse {
  role?: {
    password?: string;
  };
}

export const neonConnectionAdapter: Adapter = {
  name: "neon-connection",

  async auth(): Promise<AuthContext> {
    const envToken = process.env.NEON_API_KEY;
    if (envToken) {
      return { kind: "env", varName: "NEON_API_KEY", token: envToken };
    }
    throw new Error("neon-connection auth unavailable: set NEON_API_KEY");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const validation = validateMetadata(spec.metadata);
    if (validation) return { ok: false, error: validation };

    const projectId = spec.metadata.project_id as string;
    const branchId = spec.metadata.branch_id ?? DEFAULT_BRANCH_ID;
    const roleName = spec.metadata.role_name as string;
    const databaseName = spec.metadata.database_name as string;
    const host = spec.metadata.host as string;

    const res = await request(
      `${NEON_BASE}/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(
        branchId,
      )}/roles/${encodeURIComponent(roleName)}/reset_password`,
      {
        method: "POST",
        headers: authHeaders(ctx),
      },
    );
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };

    const data = (await res.json()) as NeonResetPasswordResponse;
    const password = data.role?.password;
    if (!password) {
      return {
        ok: false,
        error: makeError(
          "provider_error",
          "neon-connection create: response missing role.password",
          "neon-connection",
          { retryable: false },
        ),
      };
    }

    const value = connectionString(roleName, password, host, databaseName);
    const id = `${projectId}/${branchId}/${roleName}`;

    return {
      ok: true,
      data: {
        id,
        provider: "neon-connection",
        value,
        metadata: compactMetadata({
          project_id: projectId,
          branch_id: branchId,
          role_name: roleName,
          database_name: databaseName,
          host,
          pooled_host: spec.metadata.pooled_host,
          unpooled_host: spec.metadata.unpooled_host,
          pooled_connection_string: spec.metadata.pooled_host
            ? connectionString(roleName, password, spec.metadata.pooled_host, databaseName)
            : undefined,
          unpooled_connection_string: spec.metadata.unpooled_host
            ? connectionString(roleName, password, spec.metadata.unpooled_host, databaseName)
            : undefined,
        }),
        createdAt: new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, ctx: AuthContext): Promise<RotationResult<boolean>> {
    const projectId = secret.metadata.project_id;
    if (!projectId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.project_id missing", "neon-connection"),
      };
    }
    const res = await request(`${NEON_BASE}/projects/${encodeURIComponent(projectId)}`, {
      headers: authHeaders(ctx),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(_secret: Secret, _ctx: AuthContext): Promise<RotationResult<void>> {
    return { ok: true, data: undefined };
  },
};

export default neonConnectionAdapter;

function authHeaders(ctx: AuthContext): Record<string, string> {
  return {
    Authorization: `Bearer ${ctx.token}`,
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

function validateMetadata(metadata: Record<string, string>) {
  const missing = ["project_id", "role_name", "database_name", "host"].find(
    (key) => !metadata[key],
  );
  if (!missing) return undefined;
  return makeError("invalid_spec", `metadata.${missing} is required`, "neon-connection");
}

function connectionString(
  roleName: string,
  password: string,
  host: string,
  databaseName: string,
): string {
  return `postgresql://${encodeURIComponent(roleName)}:${encodeURIComponent(
    password,
  )}@${host}/${encodeURIComponent(databaseName)}?sslmode=require`;
}

function compactMetadata(input: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(input).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

function networkError(cause: Error) {
  return makeError(
    "network_error",
    `neon-connection network error: ${cause.message}`,
    "neon-connection",
    {
      cause,
    },
  );
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `neon-connection ${op}: ${res.status}`, "neon-connection");
  }
  if (res.status === 429) {
    return makeError("rate_limited", `neon-connection ${op}: 429`, "neon-connection");
  }
  if (res.status === 404) {
    return makeError("not_found", `neon-connection ${op}: 404`, "neon-connection");
  }
  if (res.status >= 500) {
    return makeError("provider_error", `neon-connection ${op}: ${res.status}`, "neon-connection");
  }
  return makeError("provider_error", `neon-connection ${op}: ${res.status}`, "neon-connection", {
    retryable: false,
  });
}
