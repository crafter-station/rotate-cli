import { makeError, resolveRegisteredAuth } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  OwnershipOptions,
  OwnershipResult,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";
import { neonAuthDefinition } from "./auth.ts";

const NEON_BASE = process.env.NEON_API_URL ?? "https://console.neon.tech/api/v2";

interface NeonApiKey {
  id: string | number;
  key: string;
  created_at?: string | number;
  project_id?: string;
}

interface NeonUser {
  id?: string;
}

interface NeonOrganization {
  id?: string;
}

interface NeonProject {
  id?: string;
  org_id?: string;
  owner_id?: string;
}

interface EndpointProject {
  projectId?: string;
  project_id?: string;
  orgId?: string;
  org_id?: string;
}

interface AdminIdentity {
  userId?: string;
  orgIds: Set<string>;
}

type OwnershipStrategy = OwnershipResult["strategy"];

const NEON_KEY_RE = /^neon_(api|org|project)_key_[a-z0-9]{40,}$/i;
const POSTGRES_RE = /^postgres(?:ql)?:\/\//i;
const NEON_HOST_ENDPOINT_RE =
  /@((?:ep-[a-z0-9-]+?))(?:-pooler)?\.[a-z0-9-]+\.(?:aws|gcp|azure)\.neon\.tech/i;
const NEON_PROJECT_PARAM_RE = /[?&]project=(ep-[a-z0-9-]+)/i;
const adminIdentityCache = new Map<string, Promise<AdminIdentity>>();

export const neonAdapter: Adapter = {
  name: "neon",
  authRef: "neon",
  authDefinition: neonAuthDefinition,

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth("neon");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const projectId = spec.metadata.project_id;
    if (!projectId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.project_id is required", "neon"),
      };
    }
    const res = await fetch(`${NEON_BASE}/projects/${projectId}/api_keys`, {
      method: "POST",
      headers: authHeaders(ctx),
      body: JSON.stringify({ key_name: `rotate-cli-${Date.now()}` }),
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };
    const data = (await res.json()) as NeonApiKey;
    const keyId = String(data.id);
    return {
      ok: true,
      data: {
        id: keyId,
        provider: "neon",
        value: data.key,
        metadata: { project_id: data.project_id ?? projectId, key_id: keyId },
        createdAt: parseCreatedAt(data.created_at),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const res = await fetch(`${NEON_BASE}/users/me`, {
      headers: { Authorization: `Bearer ${secret.value}` },
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const projectId = secret.metadata.project_id;
    const keyId = secret.metadata.key_id ?? secret.id;
    if (!projectId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.project_id missing", "neon"),
      };
    }
    const res = await fetch(`${NEON_BASE}/projects/${projectId}/api_keys/${keyId}`, {
      method: "DELETE",
      headers: authHeaders(ctx),
    });
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async ownedBy(
    secretValue: string,
    ctx: AuthContext,
    opts?: OwnershipOptions,
  ): Promise<OwnershipResult> {
    const endpointId = extractEndpointId(secretValue);
    if (endpointId) {
      const hit = lookupEndpoint(endpointId, opts?.preload);
      if (!hit) {
        return unknownOwnership(
          "Neon endpoint id was decoded, but no cached admin endpoint index was available",
          "format-decode",
        );
      }
      const orgId = hit.orgId ?? hit.org_id;
      if (!orgId) {
        return unknownOwnership(
          "Neon endpoint index entry did not include an org id",
          "format-decode",
        );
      }
      const preloadOrgIds = getPreloadOrgIds(opts?.preload);
      const adminOrgIds = preloadOrgIds ?? (await getAdminIdentity(ctx))?.orgIds;
      if (!adminOrgIds) return unknownOwnership("Neon admin identity unavailable", "format-decode");
      const isSelf = adminOrgIds.has(orgId);
      return {
        verdict: isSelf ? "self" : "other",
        adminCanBill: isSelf,
        scope: "project",
        confidence: "high",
        evidence: isSelf
          ? "Neon endpoint id maps to a project in an admin-visible org"
          : "Neon endpoint id maps to a project outside the admin-visible org set",
        strategy: "format-decode",
      };
    }

    if (!NEON_KEY_RE.test(secretValue)) {
      return unknownOwnership(
        "Secret does not match a supported Neon secret shape",
        "api-introspection",
      );
    }

    const admin = await getAdminIdentity(ctx);
    if (!admin) return unknownOwnership("Neon admin identity unavailable", "api-introspection");

    const me = await fetchJson<NeonUser>(`${NEON_BASE}/users/me`, secretValue, "ownership");
    if (me.ok) {
      if (me.data.id && me.data.id === admin.userId) {
        return {
          verdict: "self",
          adminCanBill: true,
          scope: "user",
          confidence: "high",
          evidence: "Neon /users/me matched the authenticated admin user",
          strategy: "api-introspection",
        };
      }

      const orgs = await fetchJson<unknown>(`${NEON_BASE}/organizations`, secretValue, "ownership");
      if (orgs.ok) {
        const hasSharedOrg = getOrganizations(orgs.data).some(
          (org) => org.id && admin.orgIds.has(org.id),
        );
        return {
          verdict: hasSharedOrg ? "self" : "other",
          adminCanBill: hasSharedOrg,
          scope: "org",
          confidence: "high",
          evidence: hasSharedOrg
            ? "Neon key can see an organization also visible to the admin"
            : "Neon key identity did not match the admin user or admin-visible orgs",
          strategy: "api-introspection",
        };
      }
      if (isUnavailable(orgs.error.code)) return unknownFromError(orgs.error, "api-introspection");
    } else if (me.error.code !== "auth_failed") {
      return unknownFromError(me.error, "api-introspection");
    } else {
      const orgs = await fetchJson<unknown>(`${NEON_BASE}/organizations`, secretValue, "ownership");
      if (orgs.ok) {
        const hasSharedOrg = getOrganizations(orgs.data).some(
          (org) => org.id && admin.orgIds.has(org.id),
        );
        return {
          verdict: hasSharedOrg ? "self" : "other",
          adminCanBill: hasSharedOrg,
          scope: "org",
          confidence: "high",
          evidence: hasSharedOrg
            ? "Neon org key can see an organization also visible to the admin"
            : "Neon org key can only see organizations outside the admin-visible org set",
          strategy: "api-introspection",
        };
      }
      if (isUnavailable(orgs.error.code)) return unknownFromError(orgs.error, "api-introspection");
    }

    const projects = await fetchJson<unknown>(`${NEON_BASE}/projects`, secretValue, "ownership");
    if (!projects.ok) return unknownFromError(projects.error, "api-introspection");

    const visibleProjects = getProjects(projects.data);
    const hasSharedProjectOrg = visibleProjects.some(
      (project) => project.org_id && admin.orgIds.has(project.org_id),
    );
    return {
      verdict: hasSharedProjectOrg ? "self" : "other",
      adminCanBill: hasSharedProjectOrg,
      scope: "project",
      confidence: "medium",
      evidence: hasSharedProjectOrg
        ? "Neon project-scoped key can see a project in an admin-visible org"
        : "Neon project-scoped key can only see projects outside the admin-visible org set",
      strategy: "api-introspection",
    };
  },
};

export default neonAdapter;

function authHeaders(ctx: AuthContext): Record<string, string> {
  return {
    Authorization: `Bearer ${ctx.token}`,
    "Content-Type": "application/json",
  };
}

function parseCreatedAt(value: string | number | undefined): string {
  if (typeof value === "number") {
    return new Date(value > 999_999_999_999 ? value : value * 1000).toISOString();
  }
  if (value) {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  }
  return new Date().toISOString();
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `neon ${op}: ${res.status}`, "neon");
  }
  if (res.status === 429) return makeError("rate_limited", `neon ${op}: 429`, "neon");
  if (res.status === 404) return makeError("not_found", `neon ${op}: 404`, "neon");
  if (res.status >= 500) {
    return makeError("provider_error", `neon ${op}: ${res.status}`, "neon");
  }
  return makeError("provider_error", `neon ${op}: ${res.status}`, "neon", {
    retryable: false,
  });
}

function extractEndpointId(secretValue: string): string | undefined {
  if (!POSTGRES_RE.test(secretValue)) return undefined;
  return (
    secretValue.match(NEON_HOST_ENDPOINT_RE)?.[1] ?? secretValue.match(NEON_PROJECT_PARAM_RE)?.[1]
  );
}

function lookupEndpoint(endpointId: string, preload: Record<string, unknown> | undefined) {
  const index = preload?.endpointToProject;
  if (index instanceof Map) return index.get(endpointId) as EndpointProject | undefined;
  if (isRecord(index)) return index[endpointId] as EndpointProject | undefined;
  return undefined;
}

function getPreloadOrgIds(preload: Record<string, unknown> | undefined): Set<string> | undefined {
  const value = preload?.selfOrgIds;
  if (value instanceof Set) return value as Set<string>;
  if (Array.isArray(value)) return new Set(value.filter((item) => typeof item === "string"));
  return undefined;
}

async function getAdminIdentity(ctx: AuthContext): Promise<AdminIdentity | undefined> {
  let cached = adminIdentityCache.get(ctx.token);
  if (!cached) {
    cached = loadAdminIdentity(ctx.token);
    adminIdentityCache.set(ctx.token, cached);
  }
  try {
    return await cached;
  } catch {
    adminIdentityCache.delete(ctx.token);
    return undefined;
  }
}

async function loadAdminIdentity(token: string): Promise<AdminIdentity> {
  const me = await fetchJson<NeonUser>(`${NEON_BASE}/users/me`, token, "ownership");
  if (!me.ok) throw new Error(me.error.message);

  const orgs = await fetchJson<unknown>(`${NEON_BASE}/organizations`, token, "ownership");
  if (!orgs.ok) throw new Error(orgs.error.message);

  const orgIds = new Set<string>();
  for (const org of getOrganizations(orgs.data)) {
    if (org.id) orgIds.add(org.id);
  }
  return { userId: me.data.id, orgIds };
}

async function fetchJson<T>(url: string, token: string, op: string) {
  try {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) return { ok: false as const, error: fromResponse(res, op) };
    return { ok: true as const, data: (await res.json()) as T };
  } catch (cause) {
    return {
      ok: false as const,
      error: makeError(
        "network_error",
        cause instanceof Error ? `neon network error: ${cause.message}` : "neon network error",
        "neon",
        { cause },
      ),
    };
  }
}

function getOrganizations(data: unknown): NeonOrganization[] {
  if (Array.isArray(data)) return data as NeonOrganization[];
  if (isRecord(data) && Array.isArray(data.organizations)) {
    return data.organizations as NeonOrganization[];
  }
  return [];
}

function getProjects(data: unknown): NeonProject[] {
  if (Array.isArray(data)) return data as NeonProject[];
  if (isRecord(data) && Array.isArray(data.projects)) return data.projects as NeonProject[];
  return [];
}

function unknownOwnership(evidence: string, strategy: OwnershipStrategy): OwnershipResult {
  return {
    verdict: "unknown",
    adminCanBill: false,
    confidence: "low",
    evidence,
    strategy,
  };
}

function unknownFromError(error: ReturnType<typeof makeError>, strategy: OwnershipStrategy) {
  const evidence = error.code === "provider_error" ? "provider unavailable" : error.message;
  return unknownOwnership(evidence, strategy);
}

function isUnavailable(code: ReturnType<typeof makeError>["code"]) {
  return code === "rate_limited" || code === "network_error" || code === "provider_error";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
