import { existsSync, readFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  OwnershipResult,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const VERCEL_BASE = process.env.VERCEL_API_URL ?? "https://api.vercel.com";

interface VercelToken {
  id: string;
  name: string;
  type: string;
  activeAt?: number;
  createdAt: number;
  origin?: string;
  expiresAt?: number;
}

interface VercelCreateTokenResponse {
  token: VercelToken;
  bearerToken: string;
}

interface VercelCurrentTokenResponse {
  token?: {
    scopes?: Array<{ type?: string; teamId?: string }>;
  };
}

interface VercelUserResponse {
  user?: {
    id?: string;
  };
}

interface VercelTeam {
  id?: string;
  membership?: {
    role?: string;
  };
}

interface VercelTeamsResponse {
  teams?: VercelTeam[];
  pagination?: {
    next?: number | null;
  };
}

const adminUserIdCache = new Map<string, Promise<string | undefined>>();
const adminTeamsCache = new Map<string, Promise<Map<string, VercelTeam> | undefined>>();

export const vercelTokenAdapter: Adapter = {
  name: "vercel-token",

  async auth(): Promise<AuthContext> {
    for (const path of candidateAuthPaths()) {
      if (!existsSync(path)) continue;
      try {
        const data = JSON.parse(readFileSync(path, "utf8")) as { token?: string };
        if (data.token) {
          return { kind: "cli-piggyback", tool: "vercel", tokenPath: path, token: data.token };
        }
      } catch {}
    }

    const envToken = process.env.VERCEL_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "VERCEL_TOKEN", token: envToken };
    }

    throw new Error("vercel auth unavailable: run `vercel login` or set VERCEL_TOKEN");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const url = new URL(`${VERCEL_BASE}/v3/user/tokens`);
    const teamId = spec.metadata.team_id;
    const teamSlug = spec.metadata.team_slug;
    const name = spec.metadata.name ?? `rotate-cli-${spec.secretId}-${Date.now()}`;
    const expiresAt = parseExpiresAt(spec.metadata.expires_at);

    if (teamId) url.searchParams.set("teamId", teamId);
    if (teamSlug) url.searchParams.set("slug", teamSlug);
    if (spec.metadata.expires_at && expiresAt === undefined) {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "metadata.expires_at must be a millisecond timestamp",
          "vercel-token",
        ),
      };
    }

    const body: { name: string; expiresAt?: number } = { name };
    if (expiresAt !== undefined) body.expiresAt = expiresAt;

    const res = await fetch(url, {
      method: "POST",
      headers: authHeaders(ctx),
      body: JSON.stringify(body),
    });

    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };

    const data = (await res.json()) as VercelCreateTokenResponse;
    return {
      ok: true,
      data: {
        id: data.token.id,
        provider: "vercel-token",
        value: data.bearerToken,
        metadata: tokenMetadata(data.token, teamId, teamSlug),
        createdAt: new Date(data.token.createdAt).toISOString(),
        expiresAt: data.token.expiresAt ? new Date(data.token.expiresAt).toISOString() : undefined,
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const res = await fetch(`${VERCEL_BASE}/v2/user`, {
      headers: { Authorization: `Bearer ${secret.value}` },
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, ctx: AuthContext): Promise<RotationResult<void>> {
    const tokenId = secret.metadata.token_id ?? secret.id;
    if (!tokenId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.token_id missing", "vercel-token"),
      };
    }

    const res = await fetch(`${VERCEL_BASE}/v3/user/tokens/${tokenId}`, {
      method: "DELETE",
      headers: authHeaders(ctx),
    });

    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const url = new URL(`${VERCEL_BASE}/v5/user/tokens`);
    if (filter.team_id) url.searchParams.set("teamId", filter.team_id);
    if (filter.team_slug) url.searchParams.set("slug", filter.team_slug);

    const res = await fetch(url, { headers: authHeaders(ctx) });
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };

    const body = (await res.json()) as { tokens?: VercelToken[] };
    return {
      ok: true,
      data: (body.tokens ?? []).map((token) => ({
        id: token.id,
        provider: "vercel-token",
        value: "<redacted>",
        metadata: tokenMetadata(token, filter.team_id, filter.team_slug),
        createdAt: new Date(token.createdAt).toISOString(),
        expiresAt: token.expiresAt ? new Date(token.expiresAt).toISOString() : undefined,
      })),
    };
  },

  async ownedBy(secretValue: string, ctx: AuthContext): Promise<OwnershipResult> {
    try {
      const res = await fetch(`${VERCEL_BASE}/v5/user/tokens/current`, {
        headers: { Authorization: `Bearer ${secretValue}` },
      });

      if (!res.ok) return ownershipFromFailedResponse(res);

      const body = (await res.json()) as VercelCurrentTokenResponse;
      const scopes = body.token?.scopes ?? [];
      const teamScope = scopes.find((scope) => scope.type === "team" && scope.teamId);
      if (teamScope?.teamId) {
        return await teamOwnership(teamScope.teamId, ctx);
      }

      const userScope = scopes.find((scope) => scope.type === "user");
      if (userScope) {
        return await userOwnership(secretValue, ctx);
      }

      return unknownOwnership("token introspection returned no user or team scope");
    } catch (cause) {
      makeError("network_error", "vercel-token ownedBy: network error", "vercel-token", {
        cause,
      });
      return unknownOwnership("network error during ownership check");
    }
  },
};

export default vercelTokenAdapter;

function authHeaders(ctx: AuthContext): Record<string, string> {
  return {
    Authorization: `Bearer ${ctx.token}`,
    "Content-Type": "application/json",
  };
}

async function teamOwnership(teamId: string, ctx: AuthContext): Promise<OwnershipResult> {
  const teams = await loadAdminTeams(ctx);
  if (!teams) {
    return unknownOwnership("admin team membership lookup failed");
  }

  const team = teams.get(teamId);
  if (!team) {
    return {
      verdict: "other",
      adminCanBill: false,
      scope: "team",
      confidence: "high",
      evidence: "team-scoped token; admin is not a member of the token team",
      strategy: "api-introspection",
    };
  }

  const role = team.membership?.role;
  return {
    verdict: "self",
    adminCanBill: canBill(role),
    scope: "team",
    teamRole: normalizeTeamRole(role),
    confidence: "high",
    evidence: canBill(role)
      ? "team-scoped token; admin is a billing-capable team member"
      : "team-scoped token; admin is a team member without billing control",
    strategy: "api-introspection",
  };
}

async function userOwnership(secretValue: string, ctx: AuthContext): Promise<OwnershipResult> {
  const [adminUserId, tokenUserId] = await Promise.all([
    loadAdminUserId(ctx),
    fetchUserId(secretValue),
  ]);
  if (!adminUserId || !tokenUserId) {
    return unknownOwnership("user-scoped token, but user identity lookup failed");
  }

  const self = adminUserId === tokenUserId;
  return {
    verdict: self ? "self" : "other",
    adminCanBill: self,
    scope: "user",
    confidence: "high",
    evidence: self
      ? "user-scoped token matches admin user"
      : "user-scoped token belongs to another user",
    strategy: "api-introspection",
  };
}

async function loadAdminUserId(ctx: AuthContext): Promise<string | undefined> {
  const cacheKey = `${VERCEL_BASE}:${ctx.token}`;
  let cached = adminUserIdCache.get(cacheKey);
  if (!cached) {
    cached = fetchUserId(ctx.token);
    adminUserIdCache.set(cacheKey, cached);
  }
  return cached;
}

async function loadAdminTeams(ctx: AuthContext): Promise<Map<string, VercelTeam> | undefined> {
  const cacheKey = `${VERCEL_BASE}:${ctx.token}`;
  let cached = adminTeamsCache.get(cacheKey);
  if (!cached) {
    cached = fetchTeams(ctx);
    adminTeamsCache.set(cacheKey, cached);
  }
  return cached;
}

async function fetchUserId(token: string): Promise<string | undefined> {
  const res = await fetch(`${VERCEL_BASE}/v2/user`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return undefined;
  const body = (await res.json()) as VercelUserResponse;
  return body.user?.id;
}

async function fetchTeams(ctx: AuthContext): Promise<Map<string, VercelTeam> | undefined> {
  const teams = new Map<string, VercelTeam>();
  let next: number | null | undefined;

  do {
    const url = new URL(`${VERCEL_BASE}/v2/teams`);
    if (next !== undefined && next !== null) url.searchParams.set("until", String(next));

    const res = await fetch(url, { headers: authHeaders(ctx) });
    if (!res.ok) return undefined;

    const body = (await res.json()) as VercelTeamsResponse;
    for (const team of body.teams ?? []) {
      if (team.id) teams.set(team.id, team);
    }
    next = body.pagination?.next;
  } while (next !== undefined && next !== null);

  return teams;
}

function ownershipFromFailedResponse(res: Response): OwnershipResult {
  const error = fromResponse(res, "ownedBy");
  if (error.code === "auth_failed") {
    return unknownOwnership("token is inactive, revoked, or cannot be introspected");
  }
  if (error.code === "rate_limited") {
    return unknownOwnership("rate limited while introspecting token");
  }
  if (error.code === "provider_error" && res.status >= 500) {
    return unknownOwnership("provider unavailable");
  }
  return unknownOwnership(`token introspection returned ${res.status}`);
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

function canBill(role: string | undefined): boolean {
  return role === "OWNER" || role === "BILLING";
}

function normalizeTeamRole(role: string | undefined): "admin" | "member" | "viewer" {
  if (role === "OWNER" || role === "BILLING") return "admin";
  if (role === "VIEWER") return "viewer";
  return "member";
}

function candidateAuthPaths(): string[] {
  const home = homedir();
  if (platform() === "darwin") {
    return [
      join(home, "Library", "Application Support", "com.vercel.cli", "auth.json"),
      join(home, ".local", "share", "com.vercel.cli", "auth.json"),
      join(home, ".config", "vercel", "auth.json"),
    ];
  }
  return [
    join(home, ".local", "share", "com.vercel.cli", "auth.json"),
    join(home, ".config", "vercel", "auth.json"),
  ];
}

function parseExpiresAt(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const expiresAt = Number(value);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) return undefined;
  return expiresAt;
}

function tokenMetadata(
  token: VercelToken,
  teamId: string | undefined,
  teamSlug: string | undefined,
): Record<string, string> {
  return {
    token_id: token.id,
    name: token.name,
    type: token.type,
    ...(token.origin ? { origin: token.origin } : {}),
    ...(teamId ? { team_id: teamId } : {}),
    ...(teamSlug ? { team_slug: teamSlug } : {}),
  };
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `vercel-token ${op}: ${res.status}`, "vercel-token");
  }
  if (res.status === 429) {
    return makeError("rate_limited", `vercel-token ${op}: 429`, "vercel-token");
  }
  if (res.status === 404) {
    return makeError("not_found", `vercel-token ${op}: 404`, "vercel-token");
  }
  if (res.status >= 500) {
    return makeError("provider_error", `vercel-token ${op}: ${res.status}`, "vercel-token");
  }
  return makeError("provider_error", `vercel-token ${op}: ${res.status}`, "vercel-token", {
    retryable: false,
  });
}
