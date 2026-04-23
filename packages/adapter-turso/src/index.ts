import { makeError, resolveRegisteredAuth } from "@rotate/core";
import type {
  Adapter,
  AdapterError,
  AuthContext,
  OwnershipPreload,
  OwnershipResult,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";
import { tursoAuthDefinition } from "./auth.ts";

const TURSO_API_BASE = process.env.TURSO_API_URL ?? "https://api.turso.tech";

interface TursoTokenResponse {
  jwt?: string;
}

interface TursoOrganization {
  name?: string;
  slug?: string;
}

interface TursoOrganizationsResponse {
  organizations?: Array<string | TursoOrganization>;
}

interface TursoDatabase {
  Name?: string;
  name?: string;
  Hostname?: string;
  hostname?: string;
}

interface TursoDatabasesResponse {
  databases?: TursoDatabase[];
}

interface TursoOwnershipPreload extends OwnershipPreload {
  selfOrgSlugs?: string[];
  dbIndex?: Array<{ org: string; db: string; hostname: string }>;
  error?: AdapterError;
}

export const tursoAdapter: Adapter = {
  name: "turso",
  authRef: "turso",
  authDefinition: tursoAuthDefinition,

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth("turso");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    // Merge spec.metadata with auto-resolved org/db parsed from the
    // current connection string (libsql://{db}-{org}.turso.io). Explicit
    // config still wins.
    const resolved = resolveTursoMetadata(spec);
    const merged = { ...resolved, ...spec.metadata };
    const validation = validateMetadata(merged);
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

  async ownedBy(
    secretValue: string,
    ctx: AuthContext,
    opts?: { coLocatedVars?: Record<string, string>; preload?: OwnershipPreload },
  ): Promise<OwnershipResult> {
    if (secretValue === ctx.token) {
      return {
        verdict: "self",
        adminCanBill: true,
        scope: "org",
        confidence: "high",
        evidence: "secret matches the active Turso Platform API token",
        strategy: "format-decode",
      };
    }

    const url = findLibsqlUrl(secretValue, opts?.coLocatedVars);
    if (!url) {
      if (isTursoShapedJwt(secretValue)) {
        return unknownOwnership(
          "Turso database auth tokens do not encode database or organization ownership; provide a co-located TURSO_DATABASE_URL",
        );
      }
      return unknownOwnership("no Turso libSQL URL found for ownership detection");
    }

    const parsed = parseTursoUrl(url);
    if (!parsed) return unknownOwnership("libSQL URL is not a Turso-managed hostname");

    const preload = normalizePreload(opts?.preload);
    const indexed = preload.dbIndex.get(parsed.host);
    if (indexed) {
      return {
        verdict: "self",
        adminCanBill: true,
        scope: "org",
        confidence: "high",
        evidence: `Turso hostname ${parsed.host} matches database ${indexed.db} in admin organization ${indexed.org}`,
        strategy: "list-match",
      };
    }

    let selfOrgSlugs = preload.selfOrgSlugs;
    if (selfOrgSlugs.size === 0 && !opts?.preload) {
      const loaded = await loadSelfOrgSlugs(ctx);
      if (loaded.error) {
        return unknownOwnership(ownershipErrorEvidence(loaded.error));
      }
      selfOrgSlugs = loaded.selfOrgSlugs;
    }

    if (selfOrgSlugs.size === 0) {
      return unknownOwnership("admin Turso organizations were unavailable for comparison");
    }

    if (selfOrgSlugs.has(parsed.org)) {
      return {
        verdict: "self",
        adminCanBill: true,
        scope: "org",
        confidence: "high",
        evidence: `Turso URL hostname declares organization ${parsed.org}, which is visible to the admin token`,
        strategy: "format-decode",
      };
    }

    return {
      verdict: "other",
      adminCanBill: false,
      scope: "org",
      confidence: "high",
      evidence: `Turso URL hostname declares organization ${parsed.org}, which is not visible to the admin token`,
      strategy: "format-decode",
    };
  },

  async preloadOwnership(ctx: AuthContext): Promise<OwnershipPreload> {
    const orgs = await loadSelfOrgSlugs(ctx);
    if (orgs.error) return { selfOrgSlugs: [], dbIndex: [], error: orgs.error };

    const dbIndex: Array<{ org: string; db: string; hostname: string }> = [];
    for (const org of orgs.selfOrgSlugs) {
      const res = await request(
        `${TURSO_API_BASE}/v1/organizations/${encodeURIComponent(org)}/databases`,
        {
          method: "GET",
          headers: authHeaders(ctx.token),
        },
      );
      if (res instanceof Error) continue;
      if (!res.ok) continue;

      const data = (await res.json()) as TursoDatabasesResponse;
      for (const db of data.databases ?? []) {
        const name = db.Name ?? db.name;
        const hostname = db.Hostname ?? db.hostname;
        if (name && hostname) dbIndex.push({ org, db: name, hostname });
      }
    }

    return { selfOrgSlugs: [...orgs.selfOrgSlugs], dbIndex };
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

/**
 * Parse a Turso connection string (libsql://{db}-{org}.turso.io) and
 * pick up sibling env vars (TURSO_DATABASE_URL) to auto-populate
 * metadata.organization + metadata.database. The hostname format is
 * `{database}-{organization}.turso.io` where {database} may itself
 * contain hyphens — split on the LAST hyphen before `.turso.io`.
 */
function resolveTursoMetadata(spec: RotationSpec): Record<string, string> {
  const out: Record<string, string> = {};
  const candidates = [
    spec.currentValue,
    spec.coLocatedVars?.TURSO_DATABASE_URL,
    spec.coLocatedVars?.DATABASE_URL,
  ].filter((v): v is string => typeof v === "string" && v.length > 0);
  for (const raw of candidates) {
    const parsed = parseTursoUrlForMetadata(raw);
    if (parsed) {
      if (!out.organization && parsed.organization) out.organization = parsed.organization;
      if (!out.database && parsed.database) out.database = parsed.database;
      if (!out.hostname && parsed.hostname) out.hostname = parsed.hostname;
    }
  }
  return out;
}

function parseTursoUrlForMetadata(
  raw: string,
): { database: string; organization: string; hostname: string } | undefined {
  const trimmed = raw.trim();
  if (!/^libsql:\/\//i.test(trimmed)) return undefined;
  try {
    const url = new URL(trimmed);
    const hostname = url.hostname.toLowerCase();
    // Match `{db}-{org}.turso.io`. Organization is the FINAL dash-segment
    // before `.turso.io`. Database is everything before it.
    const match = hostname.match(/^([a-z0-9-]+)-([a-z0-9]+)\.turso\.io$/);
    if (!match) return undefined;
    const [, database, organization] = match;
    if (!database || !organization) return undefined;
    return { database, organization, hostname };
  } catch {
    return undefined;
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

function findLibsqlUrl(
  secretValue: string,
  coLocatedVars: Record<string, string> | undefined,
): string | undefined {
  if (looksLikeLibsqlUrl(secretValue)) return secretValue;
  if (!coLocatedVars) return undefined;

  const exact = coLocatedVars.TURSO_DATABASE_URL ?? coLocatedVars.DATABASE_URL;
  if (exact && looksLikeLibsqlUrl(exact)) return exact;

  for (const [key, value] of Object.entries(coLocatedVars)) {
    const normalized = key.toUpperCase();
    if (normalized.includes("TURSO") && normalized.includes("URL") && looksLikeLibsqlUrl(value)) {
      return value;
    }
  }

  for (const [key, value] of Object.entries(coLocatedVars)) {
    if (key.toUpperCase().endsWith("DATABASE_URL") && looksLikeLibsqlUrl(value)) return value;
  }

  return undefined;
}

function looksLikeLibsqlUrl(value: string): boolean {
  return /^libsql:\/\//i.test(value);
}

function parseTursoUrl(value: string): { db: string; host: string; org: string } | undefined {
  try {
    const url = new URL(value.replace(/^libsql:\/\//i, "https://"));
    const host = url.host.toLowerCase();
    const suffix = ".turso.io";
    if (!host.endsWith(suffix)) return undefined;

    const hostname = host.slice(0, -suffix.length);
    const lastDash = hostname.lastIndexOf("-");
    if (lastDash <= 0 || lastDash === hostname.length - 1) return undefined;

    return {
      db: hostname.slice(0, lastDash),
      org: hostname.slice(lastDash + 1),
      host,
    };
  } catch {
    return undefined;
  }
}

function normalizePreload(preload: OwnershipPreload | undefined): {
  selfOrgSlugs: Set<string>;
  dbIndex: Map<string, { org: string; db: string; hostname: string }>;
} {
  const typed = preload as TursoOwnershipPreload | undefined;
  return {
    selfOrgSlugs: new Set((typed?.selfOrgSlugs ?? []).filter(isNonEmptyString)),
    dbIndex: new Map(
      (typed?.dbIndex ?? [])
        .filter((entry) => entry.org && entry.db && entry.hostname)
        .map((entry) => [entry.hostname.toLowerCase(), entry]),
    ),
  };
}

async function loadSelfOrgSlugs(ctx: AuthContext): Promise<{
  selfOrgSlugs: Set<string>;
  error?: AdapterError;
}> {
  const res = await request(`${TURSO_API_BASE}/v1/organizations`, {
    method: "GET",
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    return {
      selfOrgSlugs: new Set(),
      error: makeError("network_error", `turso ownership: ${res.message}`, "turso", {
        cause: res,
      }),
    };
  }
  if (!res.ok) {
    return {
      selfOrgSlugs: new Set(),
      error: ownershipErrorFromResponse(res),
    };
  }

  const data = (await res.json()) as TursoOrganizationsResponse | Array<string | TursoOrganization>;
  const organizations = Array.isArray(data) ? data : (data.organizations ?? []);
  return {
    selfOrgSlugs: new Set(
      organizations
        .map((org) => (typeof org === "string" ? org : (org.slug ?? org.name)))
        .filter(isNonEmptyString),
    ),
  };
}

function ownershipErrorFromResponse(res: Response): AdapterError {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `turso ownership: ${res.status}`, "turso");
  }
  if (res.status === 429) return makeError("rate_limited", "turso ownership: 429", "turso");
  if (res.status >= 500) {
    return makeError("provider_error", `turso ownership: ${res.status}`, "turso");
  }
  return makeError("provider_error", `turso ownership: ${res.status}`, "turso", {
    retryable: false,
  });
}

function ownershipErrorEvidence(error: AdapterError): string {
  if (error.code === "provider_error") return "provider unavailable";
  if (error.code === "rate_limited") return "ownership check rate limited";
  if (error.code === "auth_failed") return "admin Turso organization lookup failed";
  return "admin Turso organization lookup unavailable";
}

function unknownOwnership(evidence: string): OwnershipResult {
  return {
    verdict: "unknown",
    adminCanBill: false,
    confidence: "low",
    evidence,
    strategy: "format-decode",
  };
}

function isTursoShapedJwt(value: string): boolean {
  const parts = value.split(".");
  const header = parts[0];
  const payloadSegment = parts[1];
  if (!header?.startsWith("eyJ") || !payloadSegment) return false;
  const payload = decodeJwtPayload(payloadSegment);
  return Boolean(
    payload && typeof payload.exp === "number" && ("p" in payload || "iat" in payload),
  );
}

function decodeJwtPayload(segment: string): Record<string, unknown> | undefined {
  try {
    const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}
