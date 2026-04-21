import { createHash } from "node:crypto";
import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  OwnershipOptions,
  OwnershipResult,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const SUPABASE_API_BASE = process.env.SUPABASE_API_URL ?? "https://api.supabase.com";
const SUPABASE_PROJECT_BASE =
  process.env.SUPABASE_PROJECT_URL_BASE ?? "https://{project_ref}.supabase.co";

interface SupabaseApiKey {
  api_key?: string;
  id: string;
  type?: string;
  prefix?: string;
  name?: string;
  description?: string;
  hash?: string;
  inserted_at?: string;
  updated_at?: string;
}

interface SupabaseProject {
  id?: string;
}

export const supabaseAdapter: Adapter = {
  name: "supabase",

  async auth(): Promise<AuthContext> {
    const envToken = process.env.SUPABASE_ACCESS_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "SUPABASE_ACCESS_TOKEN", token: envToken };
    }
    throw new Error("supabase auth unavailable: set SUPABASE_ACCESS_TOKEN");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const projectRef = spec.metadata.project_ref;
    if (!projectRef) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.project_ref is required", "supabase"),
      };
    }

    const keyType = spec.metadata.type ?? "secret";
    const name = spec.metadata.name ?? `rotate-cli-${Date.now()}`;
    const body: Record<string, string> = { type: keyType, name };
    if (spec.reason) body.description = spec.reason;

    const res = await fetch(`${SUPABASE_API_BASE}/v1/projects/${projectRef}/api-keys?reveal=true`, {
      method: "POST",
      headers: authHeaders(ctx),
      body: JSON.stringify(body),
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };

    const data = (await res.json()) as SupabaseApiKey;
    if (!data.api_key) {
      return {
        ok: false,
        error: makeError(
          "provider_error",
          "supabase create: response did not include api_key",
          "supabase",
          { retryable: false },
        ),
      };
    }

    return {
      ok: true,
      data: {
        id: data.id,
        provider: "supabase",
        value: data.api_key,
        metadata: compactMetadata({
          project_ref: projectRef,
          key_id: data.id,
          type: data.type ?? keyType,
          name: data.name ?? name,
          prefix: data.prefix,
        }),
        createdAt: data.inserted_at ?? new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const projectRef = secret.metadata.project_ref;
    if (!projectRef) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.project_ref missing", "supabase"),
      };
    }

    const projectUrl = secret.metadata.project_url ?? projectApiUrl(projectRef);
    const res = await fetch(`${projectUrl}/rest/v1/`, {
      headers: {
        apikey: secret.value,
      },
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const projectRef = secret.metadata.project_ref;
    const keyId = secret.metadata.key_id ?? secret.id;
    if (!projectRef) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.project_ref missing", "supabase"),
      };
    }

    const res = await fetch(`${SUPABASE_API_BASE}/v1/projects/${projectRef}/api-keys/${keyId}`, {
      method: "DELETE",
      headers: authHeaders(ctx),
    });
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const projectRef = filter.project_ref;
    if (!projectRef) {
      return {
        ok: false,
        error: makeError("invalid_spec", "filter.project_ref required", "supabase"),
      };
    }

    const res = await fetch(
      `${SUPABASE_API_BASE}/v1/projects/${projectRef}/api-keys?reveal=false`,
      {
        headers: authHeaders(ctx),
      },
    );
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };

    const data = (await res.json()) as SupabaseApiKey[];
    return {
      ok: true,
      data: data.map((key) => ({
        id: key.id,
        provider: "supabase",
        value: "<redacted>",
        metadata: compactMetadata({
          project_ref: projectRef,
          key_id: key.id,
          type: key.type,
          name: key.name,
          prefix: key.prefix,
        }),
        createdAt: key.inserted_at ?? new Date(0).toISOString(),
      })),
    };
  },

  async ownedBy(
    secretValue: string,
    ctx: AuthContext,
    opts?: OwnershipOptions,
  ): Promise<OwnershipResult> {
    const urlProjectRef = projectRefFromUrl(
      opts?.coLocatedVars?.SUPABASE_URL ?? opts?.coLocatedVars?.NEXT_PUBLIC_SUPABASE_URL,
    );
    if (urlProjectRef) {
      return ownedByProjectRef(urlProjectRef, ctx, opts, "sibling-inheritance");
    }

    const jwtPayload = decodeSupabaseJwt(secretValue);
    if (jwtPayload?.iss === "supabase" && typeof jwtPayload.ref === "string") {
      return ownedByProjectRef(jwtPayload.ref, ctx, opts, "format-decode");
    }

    if (isOpaqueSupabaseKey(secretValue)) {
      return ownedByOpaqueKey(secretValue, ctx);
    }

    return unknownOwnership(
      "secret format does not expose a Supabase project ref",
      "prompt",
      "low",
    );
  },
};

export default supabaseAdapter;

function authHeaders(ctx: AuthContext): Record<string, string> {
  return {
    Authorization: `Bearer ${ctx.token}`,
    "Content-Type": "application/json",
  };
}

function projectApiUrl(projectRef: string): string {
  return SUPABASE_PROJECT_BASE.replace("{project_ref}", projectRef).replace(/\/$/, "");
}

function compactMetadata(metadata: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(metadata).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
}

async function ownedByProjectRef(
  projectRef: string,
  ctx: AuthContext,
  opts: OwnershipOptions | undefined,
  strategy: "format-decode" | "sibling-inheritance",
): Promise<OwnershipResult> {
  const refs = projectRefsFromPreload(opts?.preload) ?? (await fetchProjectRefs(ctx));
  if (!refs) {
    return unknownOwnership("project list unavailable", strategy, "low");
  }

  if (refs.has(projectRef)) {
    return {
      verdict: "self",
      adminCanBill: true,
      scope: "project",
      confidence: "high",
      evidence: "Supabase project ref is visible to the authenticated admin",
      strategy,
    };
  }

  return {
    verdict: "other",
    adminCanBill: false,
    scope: "project",
    confidence: "high",
    evidence: "Supabase project ref is not visible to the authenticated admin",
    strategy,
  };
}

async function ownedByOpaqueKey(secretValue: string, ctx: AuthContext): Promise<OwnershipResult> {
  const keyIndex = await buildKeyIndex(ctx);
  if (!keyIndex) {
    return unknownOwnership("provider unavailable", "api-introspection", "low");
  }

  if (keyIndex.has(sha256(secretValue))) {
    return {
      verdict: "self",
      adminCanBill: true,
      scope: "project",
      confidence: "medium",
      evidence: "Supabase API key matched a project visible to the authenticated admin",
      strategy: "api-introspection",
    };
  }

  return {
    verdict: "unknown",
    adminCanBill: false,
    scope: "project",
    confidence: "medium",
    evidence: "Supabase API key did not match any project visible to the authenticated admin",
    strategy: "api-introspection",
  };
}

async function fetchProjectRefs(ctx: AuthContext): Promise<Set<string> | undefined> {
  const res = await safeFetch(`${SUPABASE_API_BASE}/v1/projects`, {
    headers: authHeaders(ctx),
  });
  if (!res?.ok) {
    if (res) fromResponse(res, "ownedBy");
    return undefined;
  }

  const projects = (await res.json()) as SupabaseProject[];
  return new Set(projects.map((project) => project.id).filter(isProjectRef));
}

async function buildKeyIndex(ctx: AuthContext): Promise<Map<string, string> | undefined> {
  const refs = await fetchProjectRefs(ctx);
  if (!refs) return undefined;

  const index = new Map<string, string>();
  for (const ref of refs) {
    const res = await safeFetch(`${SUPABASE_API_BASE}/v1/projects/${ref}/api-keys?reveal=true`, {
      headers: authHeaders(ctx),
    });
    if (!res?.ok) {
      if (res) fromResponse(res, "ownedBy");
      if (shouldAbortOwnershipIntrospection(res)) {
        return undefined;
      }
      continue;
    }

    const body = (await res.json()) as unknown;
    for (const key of extractApiKeyValues(body)) {
      index.set(sha256(key), ref);
    }
  }

  return index;
}

async function safeFetch(url: string, init: RequestInit): Promise<Response | undefined> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    makeError("network_error", "supabase ownership network error", "supabase", { cause });
    return undefined;
  }
}

function projectRefsFromPreload(
  preload: Record<string, unknown> | undefined,
): Set<string> | undefined {
  const refs = preload?.projectRefs;
  if (!Array.isArray(refs)) return undefined;
  return new Set(refs.filter(isProjectRef));
}

function decodeSupabaseJwt(secretValue: string): Record<string, unknown> | undefined {
  if (!secretValue.startsWith("eyJ")) return undefined;
  const payload = secretValue.split(".")[1];
  if (!payload) return undefined;

  try {
    const padded = payload
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(Math.ceil(payload.length / 4) * 4, "=");
    return JSON.parse(Buffer.from(padded, "base64").toString("utf8")) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function projectRefFromUrl(url: string | undefined): string | undefined {
  const match = url?.match(/^https?:\/\/([a-z0-9]{20})\.supabase\.co(?:\/|$)/);
  return match?.[1];
}

function isProjectRef(value: unknown): value is string {
  return typeof value === "string" && /^[a-z0-9]{20}$/.test(value);
}

function isOpaqueSupabaseKey(secretValue: string): boolean {
  return secretValue.startsWith("sb_publishable_") || secretValue.startsWith("sb_secret_");
}

function extractApiKeyValues(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(extractApiKeyValues);
  if (!value || typeof value !== "object") return [];

  const record = value as Record<string, unknown>;
  const fields = ["api_key", "secret", "publishable_key", "secret_key", "anon", "service_role"];
  return fields.flatMap((field) => {
    const fieldValue = record[field];
    return typeof fieldValue === "string" ? [fieldValue] : extractApiKeyValues(fieldValue);
  });
}

function shouldAbortOwnershipIntrospection(res: Response | undefined): boolean {
  if (!res) return true;
  return res.status === 401 || res.status === 403 || res.status === 429 || res.status >= 500;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function unknownOwnership(
  evidence: string,
  strategy: OwnershipResult["strategy"],
  confidence: OwnershipResult["confidence"],
): OwnershipResult {
  return {
    verdict: "unknown",
    adminCanBill: false,
    confidence,
    evidence,
    strategy,
  };
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `supabase ${op}: ${res.status}`, "supabase");
  }
  if (res.status === 429) return makeError("rate_limited", `supabase ${op}: 429`, "supabase");
  if (res.status === 404) return makeError("not_found", `supabase ${op}: 404`, "supabase");
  if (res.status >= 500) {
    return makeError("provider_error", `supabase ${op}: ${res.status}`, "supabase");
  }
  return makeError("provider_error", `supabase ${op}: ${res.status}`, "supabase", {
    retryable: false,
  });
}
