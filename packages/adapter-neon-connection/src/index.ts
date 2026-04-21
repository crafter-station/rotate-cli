import { makeError } from "@rotate/core";
import { resolveRegisteredAuth } from "@rotate/core/auth";
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
import { neonConnectionAuthDefinition } from "./auth.ts";

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
  authRef: "neon-connection",
  authDefinition: neonConnectionAuthDefinition,

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth("neon-connection");
  },

  async preloadOwnership(ctx: AuthContext) {
    // Build an ownership index by enumerating every Neon project (+ its
    // endpoints) the auth key can see. ownedBy() then decodes the endpoint
    // id out of the postgres connection string and looks it up here.
    //
    // `knownOrgIds` = orgs this key has access to (or "personal" for solo
    // accounts). `endpointToProject` = endpoint_id → { projectId, orgId }.
    const knownOrgIds = new Set<string>();
    const endpointToProject = new Map<
      string,
      { projectId: string; orgId: string; host?: string }
    >();
    const fetchJson = async <T>(url: string): Promise<T | null> => {
      const ctrl = new AbortController();
      const tid = setTimeout(() => ctrl.abort(), 10_000);
      try {
        const res = await fetch(url, { headers: authHeaders(ctx), signal: ctrl.signal });
        if (!res.ok) return null;
        return (await res.json()) as T;
      } catch {
        return null;
      } finally {
        clearTimeout(tid);
      }
    };
    try {
      // Step 1: enumerate projects. Neon's v2 API paginates with `cursor`.
      // Hard cap at 10 pages (1000 projects) as a safety net.
      const projects: Array<{ id: string; org_id?: string | null }> = [];
      let cursor: string | undefined;
      for (let page = 0; page < 10; page++) {
        const url = cursor
          ? `${NEON_BASE}/projects?limit=100&cursor=${encodeURIComponent(cursor)}`
          : `${NEON_BASE}/projects?limit=100`;
        const body = await fetchJson<{
          projects?: Array<{ id: string; org_id?: string | null }>;
          pagination?: { cursor?: string };
        }>(url);
        if (!body) break;
        projects.push(...(body.projects ?? []));
        cursor = body.pagination?.cursor;
        if (!cursor) break;
      }

      for (const p of projects) {
        const orgId = p.org_id || "personal";
        knownOrgIds.add(orgId);
      }

      // Step 2: enumerate endpoints per project. Parallel with concurrency=10
      // so ~30 projects take ~3s instead of 30s.
      const queue = [...projects];
      const concurrency = 10;
      await Promise.all(
        Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
          while (queue.length) {
            const proj = queue.shift();
            if (!proj) continue;
            const body = await fetchJson<{
              endpoints?: Array<{ id?: string; host?: string }>;
            }>(`${NEON_BASE}/projects/${encodeURIComponent(proj.id)}/endpoints`);
            if (!body) continue;
            const orgId = proj.org_id || "personal";
            for (const ep of body.endpoints ?? []) {
              if (ep.id) {
                endpointToProject.set(ep.id, {
                  projectId: proj.id,
                  orgId,
                  host: ep.host,
                });
              }
            }
          }
        }),
      );

      return { knownOrgIds, endpointToProject };
    } catch {
      return { knownOrgIds, endpointToProject };
    }
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
        // The index exists and has entries, but this endpoint isn't in it.
        // That's strong evidence it belongs to a Neon account the user
        // doesn't have access to — i.e. someone else's. Use "medium"
        // confidence since a partial/stale index would also match.
        if (indexHasEntries(index.endpointToProject)) {
          return ownershipResult(
            "other",
            false,
            "medium",
            `endpoint ${endpointId} not found among ${countEntries(index.endpointToProject)} endpoints visible to your Neon key — likely owned by another account`,
          );
        }
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

function indexHasEntries(endpointToProject: unknown): boolean {
  if (endpointToProject instanceof Map) return endpointToProject.size > 0;
  if (endpointToProject && typeof endpointToProject === "object") {
    return Object.keys(endpointToProject as Record<string, unknown>).length > 0;
  }
  return false;
}

function countEntries(endpointToProject: unknown): number {
  if (endpointToProject instanceof Map) return endpointToProject.size;
  if (endpointToProject && typeof endpointToProject === "object") {
    return Object.keys(endpointToProject as Record<string, unknown>).length;
  }
  return 0;
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
