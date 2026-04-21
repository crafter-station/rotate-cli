import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  OwnershipOptions,
  OwnershipPreload,
  OwnershipResult,
  OwnershipVerdict,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const NEON_BASE = process.env.NEON_API_URL ?? "https://console.neon.tech/api/v2";
const DEFAULT_BRANCH_ID = "main";
const HOST_ENDPOINT_RE =
  /@((?:ep-[a-z]+-[a-z]+-[a-z0-9]+))(?:-pooler)?\.(?:[a-z0-9-]+\.)*(?:aws|gcp|azure)\.neon\.tech\.?/i;
const PROJECT_OPTION_RE =
  /(?:^|[?&])(?:options=)?(?:project=)(ep-[a-z]+-[a-z]+-[a-z0-9]+)(?:-pooler)?/i;

interface NeonResetPasswordResponse {
  role?: {
    password?: string;
  };
}

interface EndpointOwnership {
  projectId?: string;
  project_id?: string;
  orgId?: string;
  org_id?: string | null;
  host?: string;
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

  async ownedBy(
    secretValue: string,
    _ctx: AuthContext,
    opts?: OwnershipOptions,
  ): Promise<OwnershipResult> {
    try {
      const endpointId = extractEndpointId(secretValue);
      if (!endpointId) {
        return ownershipResult(
          "unknown",
          false,
          "low",
          "no Neon endpoint id found in postgres connection string",
        );
      }

      const index = ownershipIndex(opts?.preload);
      if (!index) {
        return ownershipResult(
          "unknown",
          false,
          "low",
          `endpoint ${endpointId} decoded, ownership index unavailable`,
        );
      }

      const hit = lookupEndpoint(index.endpointToProject, endpointId);
      if (!hit) {
        return ownershipResult(
          "unknown",
          false,
          "low",
          `endpoint ${endpointId} not found in ownership index`,
        );
      }

      const orgId = normalizeOrgId(hit.orgId ?? hit.org_id);
      const projectId = hit.projectId ?? hit.project_id ?? "unknown project";
      const verdict = index.knownOrgIds.has(orgId) ? "self" : "other";

      return ownershipResult(
        verdict,
        verdict === "self",
        "high",
        verdict === "self"
          ? `endpoint ${endpointId} maps to project ${projectId} in owned org ${orgId}`
          : `endpoint ${endpointId} maps to project ${projectId} in org ${orgId} outside known orgs`,
        "project",
      );
    } catch {
      return ownershipResult(
        "unknown",
        false,
        "low",
        "ownership detection failed before provider mutation",
      );
    }
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

function extractEndpointId(secretValue: string): string | undefined {
  const trimmed = stripQuotes(secretValue.trim());
  if (!trimmed.startsWith("postgres://") && !trimmed.startsWith("postgresql://")) {
    return undefined;
  }

  const hostMatch = trimmed.match(HOST_ENDPOINT_RE);
  if (hostMatch?.[1]) return hostMatch[1].toLowerCase();

  const decoded = decodeURIComponentSafe(trimmed);
  const optionMatch = decoded.match(PROJECT_OPTION_RE);
  return optionMatch?.[1]?.toLowerCase();
}

function stripQuotes(value: string): string {
  const first = value[0];
  const last = value[value.length - 1];
  if ((first === `"` && last === `"`) || (first === `'` && last === `'`)) {
    return value.slice(1, -1);
  }
  return value;
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function ownershipIndex(preload: OwnershipPreload | undefined) {
  if (!preload) return undefined;

  const knownOrgIds = stringSet(preload.knownOrgIds);
  const endpointToProject = preload.endpointToProject;
  if (!knownOrgIds || !endpointToProject) return undefined;

  knownOrgIds.add("personal");
  return { knownOrgIds, endpointToProject };
}

function stringSet(value: unknown): Set<string> | undefined {
  if (value instanceof Set) {
    return new Set([...value].filter((entry): entry is string => typeof entry === "string"));
  }
  if (Array.isArray(value)) {
    return new Set(value.filter((entry): entry is string => typeof entry === "string"));
  }
  if (value && typeof value === "object") {
    return new Set(
      Object.entries(value)
        .filter(([, enabled]) => Boolean(enabled))
        .map(([key]) => key),
    );
  }
  return undefined;
}

function lookupEndpoint(
  endpointToProject: unknown,
  endpointId: string,
): EndpointOwnership | undefined {
  if (endpointToProject instanceof Map) {
    return normalizeEndpoint(endpointToProject.get(endpointId));
  }
  if (endpointToProject && typeof endpointToProject === "object") {
    return normalizeEndpoint((endpointToProject as Record<string, unknown>)[endpointId]);
  }
  return undefined;
}

function normalizeEndpoint(value: unknown): EndpointOwnership | undefined {
  if (!value || typeof value !== "object") return undefined;
  return value as EndpointOwnership;
}

function normalizeOrgId(value: string | null | undefined): string {
  return value || "personal";
}

function ownershipResult(
  verdict: OwnershipVerdict,
  adminCanBill: boolean,
  confidence: OwnershipResult["confidence"],
  evidence: string,
  scope?: OwnershipResult["scope"],
): OwnershipResult {
  return {
    verdict,
    adminCanBill,
    scope,
    confidence,
    evidence,
    strategy: "format-decode",
  };
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
