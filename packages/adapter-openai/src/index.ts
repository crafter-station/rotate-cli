import { makeError } from "@rotate/core";
import { resolveRegisteredAuth } from "@rotate/core/auth";
import type {
  Adapter,
  AuthContext,
  OwnershipOptions,
  OwnershipPreload,
  OwnershipResult,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";
import { openaiAuthDefinition, verifyOpenAIAuth } from "./auth.ts";

const OPENAI_API_BASE = process.env.OPENAI_API_BASE ?? "https://api.openai.com/v1";
// Kept for back-compat with the old env override, but no longer used by
// create/revoke/list — those endpoints only rotate admin keys, not the
// project keys we discover via scan (sk-proj-*).
const OPENAI_ADMIN_KEYS_BASE =
  process.env.OPENAI_ADMIN_KEYS_URL ?? `${OPENAI_API_BASE}/organization/admin_api_keys`;
const OPENAI_ME_URL = process.env.OPENAI_ME_URL ?? `${OPENAI_API_BASE}/me`;

interface OpenAIProject {
  id: string;
  name?: string;
  status?: string;
}

interface OpenAIProjectListResponse {
  data?: OpenAIProject[];
  has_more?: boolean;
  last_id?: string;
}

interface OpenAIProjectApiKey {
  id: string;
  name?: string;
  redacted_value?: string;
  value?: string;
  created_at: number;
  last_used_at?: number | null;
  owner?: {
    type?: string;
    user?: { id?: string; name?: string; email?: string; role?: string };
    service_account?: { id?: string; name?: string; role?: string };
  };
}

interface OpenAIProjectApiKeyListResponse {
  data?: OpenAIProjectApiKey[];
  has_more?: boolean;
  last_id?: string;
}

interface OpenAIMeResponse {
  object?: string;
  id?: string;
  orgs?: {
    data?: Array<{
      id?: string;
      title?: string;
    }>;
  };
}

type OpenAIOwnershipContext = AuthContext & {
  knownOrgIds?: Iterable<string>;
  knownUserIds?: Iterable<string>;
};

export const openaiAdapter: Adapter = {
  name: "openai",
  authRef: "openai",
  authDefinition: openaiAuthDefinition,

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth("openai");
  },

  /**
   * Enumerate every project + every project key the admin token can see,
   * and build two fingerprints:
   *  - knownOrgIds / knownUserIds: used by ownedBy() for self/other verdicts.
   *  - redactedPrefixToKey: redacted_value (first 8 chars of the key) →
   *    { projectId, keyId }. create() uses this to resolve project_id
   *    from the current secret value with zero extra API calls.
   */
  async preloadOwnership(ctx: AuthContext): Promise<OwnershipPreload> {
    const knownOrgIds = new Set<string>();
    const knownUserIds = new Set<string>();
    const redactedPrefixToKey = new Map<string, { projectId: string; keyId: string }>();

    // /v1/me returns the orgs the admin key belongs to. Used for ownedBy.
    const meRes = await request(OPENAI_ME_URL, { headers: authHeaders(ctx.token) });
    if (!(meRes instanceof Error) && meRes.ok) {
      const me = (await meRes.json()) as {
        id?: string;
        orgs?: { data?: Array<{ id?: string }> };
      };
      if (me.id) knownUserIds.add(me.id);
      for (const org of me.orgs?.data ?? []) {
        if (org.id) knownOrgIds.add(org.id);
      }
    }

    // Enumerate projects, then keys per project. Each page is 100 rows.
    let projectCursor: string | null = null;
    const projects: OpenAIProject[] = [];
    for (let page = 0; page < 50; page++) {
      const qs = new URLSearchParams({ limit: "100" });
      if (projectCursor) qs.set("after", projectCursor);
      const res = await request(`${OPENAI_API_BASE}/organization/projects?${qs}`, {
        headers: authHeaders(ctx.token),
      });
      if (res instanceof Error || !res.ok) break;
      const body = (await res.json()) as OpenAIProjectListResponse;
      projects.push(...(body.data ?? []));
      if (!body.has_more || !body.last_id) break;
      projectCursor = body.last_id;
    }

    // Fan out key listing in parallel but bounded so we do not hammer the API.
    const concurrency = 8;
    const queue = [...projects];
    await Promise.all(
      Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
        while (queue.length) {
          const proj = queue.shift();
          if (!proj) continue;
          let keyCursor: string | null = null;
          for (let page = 0; page < 20; page++) {
            const qs = new URLSearchParams({ limit: "100" });
            if (keyCursor) qs.set("after", keyCursor);
            const res = await request(
              `${OPENAI_API_BASE}/organization/projects/${proj.id}/api_keys?${qs}`,
              { headers: authHeaders(ctx.token) },
            );
            if (res instanceof Error || !res.ok) break;
            const body = (await res.json()) as OpenAIProjectApiKeyListResponse;
            for (const key of body.data ?? []) {
              if (!key.id) continue;
              if (key.redacted_value) {
                const prefix = normalizeRedacted(key.redacted_value);
                if (prefix) redactedPrefixToKey.set(prefix, { projectId: proj.id, keyId: key.id });
              }
            }
            if (!body.has_more || !body.last_id) break;
            keyCursor = body.last_id;
          }
        }
      }),
    );

    return {
      knownOrgIds,
      knownUserIds,
      redactedPrefixToKey,
    };
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const projectId = spec.metadata.project_id ?? resolveProjectId(spec);
    if (!projectId) {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "metadata.project_id is required (could not auto-resolve from current value redacted prefix)",
          "openai",
        ),
      };
    }
    const name = spec.metadata.name ?? `rotate-cli-${spec.secretId}-${Date.now()}`;
    const res = await request(`${OPENAI_API_BASE}/organization/projects/${projectId}/api_keys`, {
      method: "POST",
      headers: authHeaders(ctx.token),
      body: JSON.stringify({ name }),
    });
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };
    const data = (await res.json()) as OpenAIProjectApiKey;
    if (!data.value) {
      return {
        ok: false,
        error: makeError("provider_error", "openai create: response missing key value", "openai", {
          retryable: false,
        }),
      };
    }
    return {
      ok: true,
      data: {
        id: data.id,
        provider: "openai",
        value: data.value,
        metadata: compactMetadata({
          key_id: data.id,
          project_id: projectId,
          name: data.name,
          redacted_value: data.redacted_value,
          owner_type: data.owner?.type,
          owner_email: data.owner?.user?.email,
        }),
        createdAt: new Date(data.created_at * 1000).toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    // New project keys can take a few seconds to propagate for inference calls,
    // but /v1/models responds as soon as the key record exists. Use /v1/models
    // rather than /v1/me so we verify the NEW key (project-scoped) not the
    // admin token.
    const res = await request(`${OPENAI_API_BASE}/models?limit=1`, {
      headers: authHeaders(secret.value),
    });
    if (res instanceof Error) {
      return {
        ok: false,
        error: makeError("network_error", `openai network error: ${res.message}`, "openai", {
          cause: res,
        }),
      };
    }
    if (res.ok) return { ok: true, data: true };
    return { ok: false, error: fromStatus(res.status, "verify") };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const projectId = secret.metadata.project_id;
    const keyId = secret.metadata.key_id ?? secret.id;
    if (!projectId) {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "metadata.project_id is required on the old secret for revoke",
          "openai",
          { retryable: false },
        ),
      };
    }
    const res = await request(
      `${OPENAI_API_BASE}/organization/projects/${projectId}/api_keys/${keyId}`,
      {
        method: "DELETE",
        headers: authHeaders(ctx.token),
      },
    );
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const projectId = filter.project_id;
    if (!projectId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "filter.project_id is required for list", "openai"),
      };
    }
    const limit = filter.limit ?? "20";
    const after = filter.after ? `&after=${encodeURIComponent(filter.after)}` : "";
    const res = await request(
      `${OPENAI_API_BASE}/organization/projects/${projectId}/api_keys?limit=${encodeURIComponent(limit)}${after}`,
      {
        headers: authHeaders(ctx.token),
      },
    );
    if (res instanceof Error) return { ok: false, error: networkError(res) };
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };
    const body = (await res.json()) as OpenAIProjectApiKeyListResponse;
    return {
      ok: true,
      data: (body.data ?? []).map((key) => ({
        id: key.id,
        provider: "openai",
        value: "<redacted>",
        metadata: compactMetadata({
          key_id: key.id,
          project_id: projectId,
          name: key.name,
          redacted_value: key.redacted_value,
        }),
        createdAt: new Date(key.created_at * 1000).toISOString(),
      })),
    };
  },

  async ownedBy(
    secretValue: string,
    ctx: AuthContext,
    opts?: OwnershipOptions,
  ): Promise<OwnershipResult> {
    // Fast path: the preload enumerated every project key visible to the
    // admin. Match the candidate key's trailing 4 chars against the
    // redacted_value index. Zero network calls when preload is warm.
    const fingerprint = redactedFingerprint(secretValue);
    if (fingerprint) {
      const map = opts?.preload?.redactedPrefixToKey;
      const hit =
        map instanceof Map
          ? (map.get(fingerprint) as { projectId?: string } | undefined)
          : map && typeof map === "object"
            ? (map as Record<string, { projectId?: string }>)[fingerprint]
            : undefined;
      if (hit?.projectId) {
        return {
          verdict: "self",
          adminCanBill: true,
          scope: "org",
          confidence: "high",
          evidence: `OpenAI project key fingerprint matched project ${hit.projectId} in the admin key's org`,
          strategy: "list-match",
        };
      }
      // Preload is warm AND the fingerprint is NOT in the admin's projects
      // → strong signal that the key belongs to another org. We keep
      // confidence medium because a brand-new key created after preload
      // would also miss; but the cost of a false "other" is a skip the
      // user can override with --force-rotate-other.
      const mapSize =
        map instanceof Map
          ? map.size
          : map && typeof map === "object"
            ? Object.keys(map).length
            : 0;
      if (mapSize > 0) {
        return {
          verdict: "other",
          adminCanBill: false,
          scope: "org",
          confidence: "medium",
          evidence: `OpenAI project key fingerprint (${fingerprint}) not found among ${mapSize} keys visible to the admin — likely owned by another org`,
          strategy: "list-match",
        };
      }
    }

    // Slow fallback: /v1/me with the candidate key. Only reached when the
    // preload was empty / failed. Keeps the legacy behavior intact.
    const res = await request(OPENAI_ME_URL, {
      headers: authHeaders(secretValue),
    });
    if (res instanceof Error)
      return unknownOwnership("network error during OpenAI ownership check");
    if (!res.ok) return ownershipFromFailedResponse(res);

    let me: OpenAIMeResponse;
    try {
      me = (await res.json()) as OpenAIMeResponse;
    } catch {
      return unknownOwnership("OpenAI ownership response was not valid JSON");
    }

    const knownUserIds = ownershipSet(ctx, opts, "knownUserIds");
    const knownOrgIds = ownershipSet(ctx, opts, "knownOrgIds");
    const userId = typeof me.id === "string" ? me.id : undefined;
    const orgIds = (me.orgs?.data ?? [])
      .map((org) => org.id)
      .filter((id): id is string => typeof id === "string" && id.length > 0);

    if (userId && knownUserIds.has(userId)) {
      return {
        verdict: "self",
        adminCanBill: true,
        scope: "user",
        confidence: "high",
        evidence: "OpenAI /v1/me returned a user id present in the admin ownership context",
        strategy: "api-introspection",
      };
    }

    if (orgIds.some((id) => knownOrgIds.has(id))) {
      return {
        verdict: "self",
        adminCanBill: true,
        scope: "org",
        confidence: "high",
        evidence:
          "OpenAI /v1/me returned an organization id present in the admin ownership context",
        strategy: "api-introspection",
      };
    }

    if (orgIds.length > 0 && (knownOrgIds.size > 0 || knownUserIds.size > 0)) {
      return {
        verdict: "other",
        adminCanBill: false,
        scope: "org",
        confidence: "high",
        evidence: "OpenAI /v1/me returned organization ids outside the admin ownership context",
        strategy: "api-introspection",
      };
    }

    return unknownOwnership("OpenAI /v1/me did not return enough ownership data to match this key");
  },
};

export default openaiAdapter;

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

function compactMetadata(input: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(input).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

function networkError(cause: Error) {
  return makeError("network_error", `openai network error: ${cause.message}`, "openai", { cause });
}

function fromResponse(res: Response, op: string) {
  return fromStatus(res.status, op);
}

function fromStatus(status: number, op: string) {
  if (status === 401 || status === 403) {
    return makeError("auth_failed", `openai ${op}: ${status}`, "openai");
  }
  if (status === 429) return makeError("rate_limited", `openai ${op}: 429`, "openai");
  if (status === 404) return makeError("not_found", `openai ${op}: 404`, "openai");
  if (status >= 500) {
    return makeError("provider_error", `openai ${op}: ${status}`, "openai");
  }
  return makeError("provider_error", `openai ${op}: ${status}`, "openai", {
    retryable: false,
  });
}

function ownershipSet(
  ctx: AuthContext,
  opts: OwnershipOptions | undefined,
  key: "knownOrgIds" | "knownUserIds",
): Set<string> {
  const fromCtx = (ctx as OpenAIOwnershipContext)[key];
  const fromPreload = opts?.preload?.[key];
  const source = fromCtx ?? (isIterableStringSource(fromPreload) ? fromPreload : undefined);
  return new Set(source ?? []);
}

function isIterableStringSource(value: unknown): value is Iterable<string> {
  return typeof value === "object" && value !== null && Symbol.iterator in value;
}

function ownershipFromFailedResponse(res: Response): OwnershipResult {
  const error = fromResponse(res, "ownedBy");
  if (error.code === "rate_limited")
    return unknownOwnership("OpenAI ownership check was rate limited");
  if (error.code === "provider_error" && res.status >= 500) {
    return unknownOwnership("provider unavailable");
  }
  if (error.code === "auth_failed") {
    return unknownOwnership("OpenAI rejected ownership introspection credentials");
  }
  return unknownOwnership(`OpenAI ownership check returned HTTP ${res.status}`);
}

function unknownOwnership(evidence: string): OwnershipResult {
  return {
    verdict: "unknown",
    adminCanBill: false,
    confidence: "low",
    evidence,
    strategy: "api-introspection",
  };
}

/**
 * OpenAI redacts project keys as `sk-proj-***...***XXXX` where the last 4
 * characters are plaintext and stable. The fingerprint is just the last 4
 * chars of the key, which the redacted form preserves. Entropy is enough
 * that collisions across a single org are effectively zero.
 */
function normalizeRedacted(redacted: string): string | undefined {
  const v = redacted.trim();
  if (!v) return undefined;
  // Take the trailing 4 non-asterisk characters as the fingerprint.
  const match = v.match(/([^*]{4})$/);
  return match?.[1];
}

function redactedFingerprint(fullKey: string): string | undefined {
  const clean = fullKey.trim();
  if (clean.length < 4) return undefined;
  return clean.slice(-4);
}

/**
 * Auto-resolve metadata.project_id by matching the current value against the
 * preloaded redacted_value → projectId map. Returns undefined when the
 * fingerprint is not in the preload (the key lives in an org the admin
 * token cannot see, or the preload was not warmed).
 */
function resolveProjectId(spec: RotationSpec): string | undefined {
  const current = spec.currentValue?.trim();
  if (!current) return undefined;
  const fingerprint = redactedFingerprint(current);
  if (!fingerprint) return undefined;
  const map = spec.preload?.redactedPrefixToKey;
  if (map instanceof Map) {
    const hit = map.get(fingerprint) as { projectId: string; keyId: string } | undefined;
    return hit?.projectId;
  }
  if (map && typeof map === "object") {
    const entry = (map as Record<string, { projectId?: string }>)[fingerprint];
    return entry?.projectId;
  }
  return undefined;
}
