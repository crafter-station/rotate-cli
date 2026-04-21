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
const AI_GATEWAY_BASE = process.env.AI_GATEWAY_API_URL ?? "https://ai-gateway.vercel.sh";
const PROVIDER = "vercel-ai-gateway";
const AI_GATEWAY_KEY_RE = /^vck_[A-Za-z0-9_-]{32,}$/;

interface VercelToken {
  id: string;
  name: string;
  type: string;
  activeAt?: number;
  createdAt?: number;
  origin?: string;
  expiresAt?: number;
}

interface VercelCreateTokenResponse {
  token: VercelToken;
  bearerToken: string;
}

interface VercelTeam {
  id: string;
  slug?: string;
  membership?: {
    role?: string;
  };
}

export const aiGatewayAdapter: Adapter = {
  name: PROVIDER,

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
    const teamId = spec.metadata.teamId ?? spec.metadata.team_id;
    const teamSlug = spec.metadata.teamSlug ?? spec.metadata.team_slug;
    const name = spec.metadata.name ?? `ai-gateway-rotated-${Date.now()}`;
    const expiresAt = parseExpiresAt(spec.metadata.expiresAt ?? spec.metadata.expires_at);

    if (teamId) url.searchParams.set("teamId", teamId);
    if (teamSlug) url.searchParams.set("slug", teamSlug);
    if ((spec.metadata.expiresAt ?? spec.metadata.expires_at) && expiresAt === undefined) {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "metadata.expiresAt must be a millisecond timestamp",
          PROVIDER,
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
        provider: PROVIDER,
        value: data.bearerToken,
        metadata: tokenMetadata(data.token, teamId, teamSlug),
        createdAt: new Date(data.token.createdAt ?? Date.now()).toISOString(),
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
        error: makeError("invalid_spec", "metadata.token_id missing", PROVIDER),
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
    const teamId = filter.teamId ?? filter.team_id;
    const teamSlug = filter.teamSlug ?? filter.team_slug;
    if (teamId) url.searchParams.set("teamId", teamId);
    if (teamSlug) url.searchParams.set("slug", teamSlug);

    const res = await fetch(url, { headers: authHeaders(ctx) });
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };

    const body = (await res.json()) as { tokens?: VercelToken[] };
    return {
      ok: true,
      data: (body.tokens ?? []).map((token) => ({
        id: token.id,
        provider: PROVIDER,
        value: "<redacted>",
        metadata: tokenMetadata(token, teamId, teamSlug),
        createdAt: new Date(token.createdAt ?? 0).toISOString(),
        expiresAt: token.expiresAt ? new Date(token.expiresAt).toISOString() : undefined,
      })),
    };
  },

  async ownedBy(secretValue: string, ctx: AuthContext): Promise<OwnershipResult> {
    const oidc = decodeOidcOwner(secretValue);
    if (oidc.kind === "team") {
      const teams = await fetchAdminTeams(ctx);
      if (!teams.ok) return unknown(teams.evidence);
      const team = teams.teams.find((candidate) => candidate.id === oidc.ownerId);
      if (!team) {
        return {
          verdict: "other",
          scope: "team",
          adminCanBill: false,
          confidence: "high",
          evidence: "OIDC token encodes a team owner outside the admin's Vercel teams",
          strategy: "format-decode",
        };
      }
      const role = normalizeTeamRole(team.membership?.role);
      return {
        verdict: "self",
        scope: "team",
        teamRole: role,
        adminCanBill: canBill(team.membership?.role),
        confidence: "high",
        evidence: "OIDC token encodes a team owner that matches the admin's Vercel teams",
        strategy: "format-decode",
      };
    }

    if (secretValue.startsWith("eyJ")) {
      return unknown("OIDC token format detected but owner_id could not be decoded");
    }

    if (!AI_GATEWAY_KEY_RE.test(secretValue)) {
      return unknown("not an AI Gateway key format; expected vck_ prefix");
    }

    const alive = await probeAiGatewayKey(secretValue);
    if (!alive.ok) return unknown(alive.evidence);

    const teams = await fetchAdminTeams(ctx);
    if (!teams.ok) return unknown(teams.evidence);

    if (teams.teams.length === 1) {
      const team = teams.teams[0];
      const role = normalizeTeamRole(team?.membership?.role);
      return {
        verdict: "self",
        scope: "team",
        teamRole: role,
        adminCanBill: canBill(team?.membership?.role),
        confidence: "medium",
        evidence:
          "AI Gateway key is alive and admin belongs to exactly one Vercel team; assumed same team",
        strategy: "format-decode",
      };
    }

    return unknown("AI Gateway key is alive but admin team membership is ambiguous");
  },
};

export default aiGatewayAdapter;

function authHeaders(ctx: AuthContext): Record<string, string> {
  return {
    Authorization: `Bearer ${ctx.token}`,
    "Content-Type": "application/json",
  };
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
    ...(teamId ? { teamId, team_id: teamId } : {}),
    ...(teamSlug ? { teamSlug, team_slug: teamSlug } : {}),
  };
}

function unknown(evidence: string): OwnershipResult {
  return {
    verdict: "unknown",
    scope: "team",
    adminCanBill: false,
    confidence: "low",
    evidence,
    strategy: "format-decode",
  };
}

async function probeAiGatewayKey(
  secretValue: string,
): Promise<{ ok: true } | { ok: false; evidence: string }> {
  try {
    const res = await fetch(`${AI_GATEWAY_BASE}/v1/models`, {
      headers: { Authorization: `Bearer ${secretValue}` },
    });
    if (res.status === 401 || res.status === 403) {
      makeError("auth_failed", `${PROVIDER} ownership: ${res.status}`, PROVIDER);
      return { ok: false, evidence: "AI Gateway key revoked or invalid" };
    }
    if (res.status === 429) {
      makeError("rate_limited", `${PROVIDER} ownership: 429`, PROVIDER);
      return { ok: false, evidence: "AI Gateway ownership check rate limited" };
    }
    if (res.status >= 500) {
      makeError("provider_error", `${PROVIDER} ownership: ${res.status}`, PROVIDER);
      return { ok: false, evidence: "provider unavailable" };
    }
    if (!res.ok) {
      return { ok: false, evidence: `AI Gateway liveness probe returned ${res.status}` };
    }
    return { ok: true };
  } catch {
    return { ok: false, evidence: "AI Gateway ownership check network error" };
  }
}

async function fetchAdminTeams(
  ctx: AuthContext,
): Promise<{ ok: true; teams: VercelTeam[] } | { ok: false; evidence: string }> {
  try {
    const res = await fetch(`${VERCEL_BASE}/v2/teams`, { headers: authHeaders(ctx) });
    if (res.status === 401 || res.status === 403) {
      makeError("auth_failed", `${PROVIDER} ownership teams: ${res.status}`, PROVIDER);
      return { ok: false, evidence: "admin Vercel token cannot list teams" };
    }
    if (res.status === 429) {
      makeError("rate_limited", `${PROVIDER} ownership teams: 429`, PROVIDER);
      return { ok: false, evidence: "admin team lookup rate limited" };
    }
    if (res.status >= 500) {
      makeError("provider_error", `${PROVIDER} ownership teams: ${res.status}`, PROVIDER);
      return { ok: false, evidence: "provider unavailable" };
    }
    if (!res.ok) return { ok: false, evidence: `admin team lookup returned ${res.status}` };

    const body = (await res.json()) as { teams?: VercelTeam[] };
    return { ok: true, teams: body.teams ?? [] };
  } catch {
    return { ok: false, evidence: "admin team lookup network error" };
  }
}

function decodeOidcOwner(
  secretValue: string,
): { kind: "team"; ownerId: string } | { kind: "none" } {
  if (!secretValue.startsWith("eyJ")) return { kind: "none" };
  const [, payload] = secretValue.split(".");
  if (!payload) return { kind: "none" };
  try {
    const decoded = JSON.parse(
      Buffer.from(base64UrlToBase64(payload), "base64").toString("utf8"),
    ) as {
      owner_id?: unknown;
    };
    if (typeof decoded.owner_id === "string" && decoded.owner_id.startsWith("team_")) {
      return { kind: "team", ownerId: decoded.owner_id };
    }
  } catch {}
  return { kind: "none" };
}

function base64UrlToBase64(value: string): string {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  return normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
}

function normalizeTeamRole(role: string | undefined): "admin" | "member" | "viewer" | undefined {
  const normalized = role?.toLowerCase();
  if (!normalized) return undefined;
  if (normalized === "owner" || normalized === "billing" || normalized === "admin") return "admin";
  if (normalized === "viewer") return "viewer";
  return "member";
}

function canBill(role: string | undefined): boolean {
  const normalized = role?.toLowerCase();
  return normalized === "owner" || normalized === "billing" || normalized === "admin";
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `${PROVIDER} ${op}: ${res.status}`, PROVIDER);
  }
  if (res.status === 429) {
    return makeError("rate_limited", `${PROVIDER} ${op}: 429`, PROVIDER);
  }
  if (res.status === 404) {
    return makeError("not_found", `${PROVIDER} ${op}: 404`, PROVIDER);
  }
  if (res.status >= 500) {
    return makeError("provider_error", `${PROVIDER} ${op}: ${res.status}`, PROVIDER);
  }
  return makeError("provider_error", `${PROVIDER} ${op}: ${res.status}`, PROVIDER, {
    retryable: false,
  });
}
