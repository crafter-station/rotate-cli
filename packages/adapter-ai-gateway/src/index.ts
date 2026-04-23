import { makeError, resolveRegisteredAuth } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  OwnershipResult,
  PromptIO,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";
import { vercelAiGatewayAuthDefinition } from "./auth.ts";

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
  authRef: PROVIDER,
  authDefinition: vercelAiGatewayAuthDefinition,
  // Vercel AI Gateway keys (`vck_*`) live on a private surface — the
  // prior implementation posted to /v3/user/tokens, which returns a
  // generic Vercel user token (NOT a vck_* key) and hits a 32/hour
  // rate limit that trips immediately during bulk runs. Until Vercel
  // exposes a supported /ai-gateway/keys endpoint, go manual-assist.
  mode: "manual-assist",

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth(PROVIDER);
  },

  async create(spec: RotationSpec, _ctx: AuthContext): Promise<RotationResult<Secret>> {
    const io = spec.io;
    if (!io?.isInteractive) {
      return {
        ok: false,
        error: makeError(
          "unsupported",
          "Vercel AI Gateway rotation is manual-assist — re-run with --manual-only from an interactive TTY",
          PROVIDER,
          { retryable: false },
        ),
      };
    }
    io.note(
      [
        "Vercel AI Gateway keys (vck_*) do not have a supported rotation API.",
        "The /v3/user/tokens endpoint returns generic user tokens, not AI Gateway keys,",
        "and is rate-limited to 32 requests/hour so it also trips on bulk runs.",
        "",
        "Open: https://vercel.com/dashboard/ai-gateway/api-keys",
        `Target: ${spec.secretId}`,
        "",
        "Steps:",
        "1. Create a new AI Gateway key with a descriptive name.",
        "2. Copy the new key (vck_*).",
        "3. Paste it below — rotate-cli propagates to all vercel-env consumers.",
        "4. After the grace period, rotate prompts you to delete the OLD key.",
      ].join("\n"),
    );
    const value = (await io.promptSecret("Paste the new Vercel AI Gateway key")).trim();
    if (!value) {
      return {
        ok: false,
        error: makeError("invalid_spec", "pasted AI Gateway key was empty", PROVIDER),
      };
    }
    if (!AI_GATEWAY_KEY_RE.test(value)) {
      return {
        ok: false,
        error: makeError(
          "invalid_spec",
          "pasted value does not look like a Vercel AI Gateway key (expected vck_*)",
          PROVIDER,
        ),
      };
    }
    return {
      ok: true,
      data: {
        id: spec.secretId,
        provider: PROVIDER,
        value,
        metadata: { ...spec.metadata, manual_assist: "true" },
        createdAt: new Date().toISOString(),
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    // Ping the AI Gateway /v1/models endpoint with the new key. Proves the
    // vck_* is live without burning one of our 32/h generic-token budget.
    const res = await fetch(`${AI_GATEWAY_BASE}/v1/models`, {
      headers: { Authorization: `Bearer ${secret.value}` },
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(
    secret: Secret,
    _ctx: AuthContext,
    opts?: { io?: PromptIO },
  ): Promise<RotationResult<void>> {
    const io = opts?.io;
    if (!io?.isInteractive) {
      return {
        ok: false,
        error: makeError(
          "unsupported",
          "Vercel AI Gateway revoke is manual-assist — re-run with --manual-only from a TTY",
          PROVIDER,
          { retryable: false },
        ),
      };
    }
    io.note(
      [
        "Vercel AI Gateway old key cleanup is manual-assist.",
        "",
        "Open: https://vercel.com/dashboard/ai-gateway/api-keys",
        `Target: ${secret.id}`,
        "",
        "Delete the OLD key (not the one you just created).",
      ].join("\n"),
    );
    const confirmed = await io.confirm("Confirm the old AI Gateway key has been deleted", {
      initialValue: false,
    });
    if (!confirmed) {
      return {
        ok: false,
        error: makeError("unsupported", "AI Gateway revoke was not confirmed", PROVIDER),
      };
    }
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
