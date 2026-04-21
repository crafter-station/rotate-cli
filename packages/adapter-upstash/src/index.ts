import { createHash } from "node:crypto";
import { makeError } from "@rotate/core";
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

interface UpstashTeam {
  id?: string;
  team_id?: string;
  teamId?: string;
}

interface UpstashOwnershipDb {
  id: string;
  endpoint: string;
  teamId?: string | null;
  userEmail?: string;
}

interface UpstashOwnershipPreload extends OwnershipPreload {
  dbByEndpoint?: Record<string, UpstashOwnershipDb>;
  tokenHashToEndpoint?: Record<string, string>;
  selfTeamIds?: string[];
  selfEmails?: string[];
  errorCode?: string;
  errorEvidence?: string;
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
  read_only_rest_token?: string;
  readOnlyRestToken?: string;
  endpoint?: string;
  team_id?: string | null;
  teamId?: string | null;
  user_email?: string;
  userEmail?: string;
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

  async preloadOwnership(ctx: AuthContext): Promise<OwnershipPreload> {
    return preloadUpstashOwnership(ctx);
  },

  async ownedBy(
    secretValue: string,
    ctx: AuthContext,
    opts: OwnershipOptions = {},
  ): Promise<OwnershipResult> {
    try {
      const preload = asOwnershipPreload(opts.preload ?? (await preloadUpstashOwnership(ctx)));
      if (preload.errorCode) {
        return unknownOwnership(preload.errorEvidence ?? "ownership index unavailable", "low");
      }

      const restEndpoint = endpointFromRestUrl(
        opts.coLocatedVars?.UPSTASH_REDIS_REST_URL ??
          opts.coLocatedVars?.KV_REST_API_URL ??
          (looksLikeUpstashRestUrl(secretValue) ? secretValue : undefined),
      );
      if (restEndpoint) {
        const db = preload.dbByEndpoint?.[restEndpoint];
        if (!db) {
          return {
            verdict: "other",
            adminCanBill: false,
            confidence: "high",
            evidence: `Upstash Redis endpoint ${restEndpoint} is not visible to the authenticated admin`,
            strategy: "format-decode",
          };
        }
        return ownershipFromDb(
          db,
          preload,
          "format-decode",
          `Upstash Redis endpoint ${restEndpoint}`,
        );
      }

      if (looksLikeUpstashRestToken(secretValue)) {
        const endpoint = preload.tokenHashToEndpoint?.[sha256(secretValue)];
        if (!endpoint) {
          return unknownOwnership(
            "REST token did not match the authenticated admin's Upstash Redis index",
            "medium",
          );
        }
        const db = preload.dbByEndpoint?.[endpoint];
        if (!db) {
          return unknownOwnership("REST token matched an incomplete Upstash Redis index", "low");
        }
        return ownershipFromDb(
          db,
          preload,
          "list-match",
          "REST token hash matched Upstash Redis index",
        );
      }

      const redisEndpoint = endpointFromRedisUrl(
        opts.coLocatedVars?.KV_URL ??
          opts.coLocatedVars?.REDIS_URL ??
          (looksLikeRedisUrl(secretValue) ? secretValue : undefined),
      );
      if (redisEndpoint) {
        const db = preload.dbByEndpoint?.[redisEndpoint];
        if (!db) {
          return {
            verdict: "other",
            adminCanBill: false,
            confidence: "high",
            evidence: `Upstash Redis endpoint ${redisEndpoint} is not visible to the authenticated admin`,
            strategy: "format-decode",
          };
        }
        return ownershipFromDb(
          db,
          preload,
          "format-decode",
          `Upstash Redis endpoint ${redisEndpoint}`,
        );
      }

      return unknownOwnership("secret shape does not expose an Upstash Redis owner", "low");
    } catch (cause) {
      const error = cause instanceof Error ? cause : new Error(String(cause));
      networkError(error);
      return unknownOwnership(
        "ownership check failed before Upstash Redis ownership could be determined",
        "low",
      );
    }
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

async function preloadUpstashOwnership(ctx: AuthContext): Promise<UpstashOwnershipPreload> {
  const [email] = splitAuthToken(ctx.token);
  const res = await request(`${UPSTASH_API_BASE}/redis/databases`, {
    headers: authHeaders(ctx),
  });
  if (res instanceof Error) {
    const error = networkError(res);
    return {
      errorCode: error.code,
      errorEvidence: "network error while building Upstash Redis ownership index",
    };
  }
  if (!res.ok) {
    const error = fromResponse(res, "preloadOwnership");
    return {
      errorCode: error.code,
      errorEvidence: ownershipEvidenceForError(error.code),
    };
  }

  let data: UpstashDatabase[];
  try {
    data = (await res.json()) as UpstashDatabase[];
  } catch (cause) {
    const error = makeError(
      "provider_error",
      "upstash preloadOwnership: invalid JSON",
      UPSTASH_PROVIDER,
      {
        cause,
      },
    );
    return {
      errorCode: error.code,
      errorEvidence: "provider unavailable",
    };
  }

  const selfTeamIds = await loadSelfTeamIds(ctx);
  const selfEmails = email ? [email.toLowerCase()] : [];
  const dbByEndpoint: Record<string, UpstashOwnershipDb> = {};
  const tokenHashToEndpoint: Record<string, string> = {};

  for (const database of data) {
    const id = database.database_id ?? database.id;
    const endpoint = normalizeEndpoint(database.endpoint);
    if (!id || !endpoint) continue;

    dbByEndpoint[endpoint] = {
      id,
      endpoint,
      teamId: database.team_id ?? database.teamId ?? null,
      userEmail: database.user_email ?? database.userEmail,
    };

    const restToken = database.rest_token ?? database.restToken;
    const readOnlyRestToken = database.read_only_rest_token ?? database.readOnlyRestToken;
    if (restToken) tokenHashToEndpoint[sha256(restToken)] = endpoint;
    if (readOnlyRestToken) tokenHashToEndpoint[sha256(readOnlyRestToken)] = endpoint;
  }

  return {
    dbByEndpoint,
    tokenHashToEndpoint,
    selfTeamIds,
    selfEmails,
  };
}

async function loadSelfTeamIds(ctx: AuthContext): Promise<string[]> {
  const res = await request(`${UPSTASH_API_BASE}/teams`, {
    headers: authHeaders(ctx),
  });
  if (res instanceof Error || !res.ok) return [];
  try {
    const data = (await res.json()) as UpstashTeam[];
    return data.flatMap((team) => {
      const id = team.team_id ?? team.teamId ?? team.id;
      return id ? [id] : [];
    });
  } catch {
    return [];
  }
}

function asOwnershipPreload(preload: OwnershipPreload): UpstashOwnershipPreload {
  return preload as UpstashOwnershipPreload;
}

function ownershipFromDb(
  db: UpstashOwnershipDb,
  preload: UpstashOwnershipPreload,
  strategy: OwnershipResult["strategy"],
  evidencePrefix: string,
): OwnershipResult {
  const self = isSelfOwned(db, preload);
  return {
    verdict: self ? "self" : "other",
    adminCanBill: self,
    scope: db.teamId ? "team" : "user",
    confidence: "high",
    evidence: self
      ? `${evidencePrefix} matched a database owned by the authenticated Upstash admin`
      : `${evidencePrefix} matched a database outside the authenticated Upstash admin ownership set`,
    strategy,
  };
}

function isSelfOwned(db: UpstashOwnershipDb, preload: UpstashOwnershipPreload): boolean {
  if (db.teamId && preload.selfTeamIds?.includes(db.teamId)) return true;
  const dbEmail = db.userEmail?.toLowerCase();
  if (dbEmail && preload.selfEmails?.includes(dbEmail)) return true;
  return false;
}

function unknownOwnership(
  evidence: string,
  confidence: OwnershipResult["confidence"],
): OwnershipResult {
  return {
    verdict: "unknown",
    adminCanBill: false,
    confidence,
    evidence,
    strategy: "list-match",
  };
}

function ownershipEvidenceForError(code: string): string {
  if (code === "auth_failed") return "auth failed while building Upstash Redis ownership index";
  if (code === "rate_limited") return "rate limited while building Upstash Redis ownership index";
  if (code === "provider_error") return "provider unavailable";
  return "ownership index unavailable";
}

function looksLikeUpstashRestUrl(value: string): boolean {
  return /^https?:\/\/[a-z]+-[a-z]+-\d+\.upstash\.io\b/i.test(value);
}

function endpointFromRestUrl(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const match = value.match(/^https?:\/\/([a-z]+-[a-z]+-\d+)\.upstash\.io\b/i);
  return match?.[1] ? `${match[1].toLowerCase()}.upstash.io` : undefined;
}

function looksLikeRedisUrl(value: string): boolean {
  return value.startsWith("redis://") || value.startsWith("rediss://");
}

function endpointFromRedisUrl(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const match = value.match(/@([a-z]+-[a-z]+-\d+)\.upstash\.io\b/i);
  return match?.[1] ? `${match[1].toLowerCase()}.upstash.io` : undefined;
}

function normalizeEndpoint(endpoint: string | undefined): string | undefined {
  if (!endpoint) return undefined;
  const match = endpoint.match(/^([a-z]+-[a-z]+-\d+)\.upstash\.io$/i);
  return match?.[1] ? `${match[1].toLowerCase()}.upstash.io` : undefined;
}

function looksLikeUpstashRestToken(value: string): boolean {
  return /^[A-Za-z0-9_=+/-]{40,}$/.test(value);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
