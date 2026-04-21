import { makeError, resolveRegisteredAuth } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  OwnershipResult,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";
import { githubTokenAuthDefinition } from "./auth.ts";

const GITHUB_BASE = githubBaseUrl();

interface GitHubInstallationToken {
  token: string;
  expires_at: string;
  permissions?: Record<string, string>;
  repositories?: Array<{ id: number; name: string; full_name?: string }>;
  repository_selection?: string;
}

type GitHubTokenKind =
  | "pat-classic"
  | "pat-fine-grained"
  | "oauth-access"
  | "oauth-user-to-server"
  | "installation"
  | "refresh"
  | "actions"
  | "unknown";

interface GitHubAccount {
  login?: string;
  id?: number;
  type?: string;
}

interface GitHubInstallationMeta {
  account?: GitHubAccount;
}

export const githubTokenAdapter: Adapter = {
  name: "github-token",
  authRef: "github-token",
  authDefinition: githubTokenAuthDefinition,

  async auth(): Promise<AuthContext> {
    return resolveRegisteredAuth("github-token");
  },

  async create(spec: RotationSpec, ctx: AuthContext): Promise<RotationResult<Secret>> {
    const installationId = spec.metadata.installation_id;
    if (!installationId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "metadata.installation_id is required", "github"),
      };
    }
    const body = tokenRequestBody(spec.metadata);
    const res = await fetch(`${GITHUB_BASE}/app/installations/${installationId}/access_tokens`, {
      method: "POST",
      headers: authHeaders(ctx.token),
      body: JSON.stringify(body),
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "create") };
    const data = (await res.json()) as GitHubInstallationToken;
    const createdAt = new Date().toISOString();
    return {
      ok: true,
      data: {
        id: tokenId(data.token, installationId),
        provider: "github",
        value: data.token,
        metadata: {
          installation_id: installationId,
          repository_selection: data.repository_selection ?? "",
          token_last_eight: data.token.slice(-8),
        },
        createdAt,
        expiresAt: data.expires_at,
      },
    };
  },

  async verify(secret: Secret, _ctx: AuthContext): Promise<RotationResult<boolean>> {
    const res = await fetch(`${GITHUB_BASE}/installation/repositories?per_page=1`, {
      headers: authHeaders(secret.value),
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "verify") };
    return { ok: true, data: true };
  },

  async revoke(secret: Secret, _ctx: AuthContext): Promise<RotationResult<void>> {
    const res = await fetch(`${GITHUB_BASE}/installation/token`, {
      method: "DELETE",
      headers: authHeaders(secret.value),
    });
    if (res.status === 404) return { ok: true, data: undefined };
    if (!res.ok) return { ok: false, error: fromResponse(res, "revoke") };
    return { ok: true, data: undefined };
  },

  async list(filter: Record<string, string>, ctx: AuthContext): Promise<RotationResult<Secret[]>> {
    const installationId = filter.installation_id;
    if (!installationId) {
      return {
        ok: false,
        error: makeError("invalid_spec", "filter.installation_id required", "github"),
      };
    }
    const res = await fetch(`${GITHUB_BASE}/app/installations/${installationId}`, {
      headers: authHeaders(ctx.token),
    });
    if (!res.ok) return { ok: false, error: fromResponse(res, "list") };
    const data = (await res.json()) as {
      id: number;
      app_id?: number;
      app_slug?: string;
      repository_selection?: string;
      created_at?: string;
      updated_at?: string;
    };
    return {
      ok: true,
      data: [
        {
          id: `github/installation/${data.id}`,
          provider: "github",
          value: "<redacted>",
          metadata: {
            installation_id: String(data.id),
            app_id: data.app_id ? String(data.app_id) : "",
            app_slug: data.app_slug ?? "",
            repository_selection: data.repository_selection ?? "",
          },
          createdAt: data.created_at ?? data.updated_at ?? new Date(0).toISOString(),
        },
      ],
    };
  },

  async ownedBy(secretValue, ctx, opts): Promise<OwnershipResult> {
    const kind = classifyToken(secretValue);
    if (kind === "actions") {
      return {
        verdict: "other",
        adminCanBill: false,
        scope: "project",
        confidence: "high",
        evidence: "GitHub Actions token is workflow-scoped and should not be persisted",
        strategy: "api-introspection",
      };
    }
    if (kind === "refresh") {
      return unknownOwnership(
        "GitHub refresh tokens cannot be introspected without the paired access token",
        "user",
        "low",
      );
    }
    if (kind === "unknown") {
      return unknownOwnership("GitHub token prefix is not recognized", undefined, "low");
    }

    const admin = adminOwnershipContext(opts?.preload);

    try {
      if (kind === "installation") {
        const res = await fetch(`${GITHUB_BASE}/installation/repositories?per_page=1`, {
          headers: ownershipHeaders(secretValue),
        });
        if (res.status === 401 || res.status === 403) {
          makeError("auth_failed", `github ownership: ${res.status}`, "github");
          return unknownOwnership("GitHub installation token is invalid or expired", "org", "low");
        }
        if (res.status === 429) {
          makeError("rate_limited", "github ownership: 429", "github");
          return unknownOwnership("GitHub ownership check was rate limited", "org", "low");
        }
        if (res.status >= 500) {
          makeError("provider_error", `github ownership: ${res.status}`, "github");
          return unknownOwnership("GitHub provider unavailable", "org", "low");
        }
        if (!res.ok) {
          makeError("provider_error", `github ownership: ${res.status}`, "github", {
            retryable: false,
          });
          return unknownOwnership(`GitHub ownership check failed with ${res.status}`, "org", "low");
        }

        const body = (await res.json()) as {
          repositories?: Array<{ owner?: GitHubAccount }>;
        };
        const owner = body.repositories?.find((repo) => repo.owner)?.owner;
        if (!owner?.login) {
          return unknownOwnership("GitHub installation exposed no repository owner", "org", "low");
        }

        const scope = owner.type === "User" ? "user" : "org";
        const match = admin.installations.find((installation) =>
          sameAccount(installation.account, owner),
        );
        if (!admin.hasIdentity) {
          return unknownOwnership(
            `GitHub installation owner is ${owner.type ?? "Account"} ${owner.login}`,
            scope,
            "medium",
          );
        }

        const self = Boolean(match);
        return {
          verdict: self ? "self" : "other",
          adminCanBill: self && owner.type !== "Organization" && owner.login === admin.login,
          scope,
          confidence: "high",
          evidence: self
            ? `GitHub installation owner ${owner.login} is accessible to the authenticated admin`
            : `GitHub installation owner ${owner.login} is not in the authenticated admin installation set`,
          strategy: "api-introspection",
        };
      }

      const res = await fetch(`${GITHUB_BASE}/user`, {
        headers: ownershipHeaders(secretValue),
      });
      if (res.status === 401 || res.status === 403) {
        makeError("auth_failed", `github ownership: ${res.status}`, "github");
        return unknownOwnership("GitHub token is invalid or revoked", "user", "low");
      }
      if (res.status === 429) {
        makeError("rate_limited", "github ownership: 429", "github");
        return unknownOwnership("GitHub ownership check was rate limited", "user", "low");
      }
      if (res.status >= 500) {
        makeError("provider_error", `github ownership: ${res.status}`, "github");
        return unknownOwnership("GitHub provider unavailable", "user", "low");
      }
      if (!res.ok) {
        makeError("provider_error", `github ownership: ${res.status}`, "github", {
          retryable: false,
        });
        return unknownOwnership(`GitHub ownership check failed with ${res.status}`, "user", "low");
      }

      const user = (await res.json()) as { login?: string; id?: number };
      if (typeof user.id !== "number") {
        return unknownOwnership(
          "GitHub user introspection did not include a user id",
          "user",
          "low",
        );
      }

      const self = admin.userId === user.id || secretValue === ctx.token;
      if (!admin.hasIdentity && secretValue !== ctx.token) {
        return unknownOwnership(
          "GitHub token owner found, but admin identity was unavailable",
          "user",
          "medium",
        );
      }

      return {
        verdict: self ? "self" : "other",
        adminCanBill: self && kind !== "pat-fine-grained",
        scope: "user",
        confidence: "high",
        evidence: self
          ? "GitHub user token belongs to the authenticated admin"
          : "GitHub user token belongs to a different GitHub user",
        strategy: "api-introspection",
      };
    } catch (cause) {
      makeError("network_error", "github ownership network error", "github", { cause });
      return unknownOwnership(
        "GitHub ownership check failed due to a network error",
        undefined,
        "low",
      );
    }
  },
};

export default githubTokenAdapter;

function githubBaseUrl(): string {
  if (process.env.GITHUB_API_URL) return process.env.GITHUB_API_URL;
  const host = process.env.GH_HOST;
  if (!host) return "https://api.github.com";
  const normalized = host.replace(/^https?:\/\//, "").replace(/\/$/, "");
  if (normalized === "github.com") return "https://api.github.com";
  return `https://${normalized}/api/v3`;
}

function tokenRequestBody(metadata: Record<string, string>): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  if (metadata.repository_ids) {
    body.repository_ids = metadata.repository_ids
      .split(",")
      .map((id) => Number(id.trim()))
      .filter((id) => Number.isInteger(id));
  }
  if (metadata.repositories) {
    body.repositories = metadata.repositories
      .split(",")
      .map((name) => name.trim())
      .filter(Boolean);
  }
  if (metadata.permissions) {
    body.permissions = Object.fromEntries(
      metadata.permissions
        .split(",")
        .map((entry) => entry.split(":").map((part) => part.trim()))
        .filter((entry): entry is [string, string] => Boolean(entry[0]) && Boolean(entry[1])),
    );
  }
  return body;
}

function authHeaders(token: string): Record<string, string> {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    "X-GitHub-Api-Version": "2026-03-10",
  };
}

function ownershipHeaders(token: string): Record<string, string> {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

function tokenId(token: string, installationId: string): string {
  return `github/installation/${installationId}/${token.slice(-8)}`;
}

function classifyToken(value: string): GitHubTokenKind {
  if (value.startsWith("ghp_")) return "pat-classic";
  if (value.startsWith("github_pat_")) return "pat-fine-grained";
  if (value.startsWith("gho_")) return "oauth-access";
  if (value.startsWith("ghu_")) return "oauth-user-to-server";
  if (value.startsWith("ghs_")) return "installation";
  if (value.startsWith("ghr_")) return "refresh";
  if (/^ghb_|^ghac_/.test(value) || value.length > 60) return "actions";
  return "unknown";
}

function unknownOwnership(
  evidence: string,
  scope: OwnershipResult["scope"],
  confidence: OwnershipResult["confidence"],
): OwnershipResult {
  return {
    verdict: "unknown",
    adminCanBill: false,
    ...(scope ? { scope } : {}),
    confidence,
    evidence,
    strategy: "api-introspection",
  };
}

function adminOwnershipContext(preload: Record<string, unknown> | undefined) {
  const userId = numberValue(preload?.adminUserId);
  const login = stringValue(preload?.adminLogin);
  return {
    userId,
    login,
    installations: installationValues(preload),
    hasIdentity: userId !== undefined || login !== undefined,
  };
}

function installationValues(
  preload: Record<string, unknown> | undefined,
): GitHubInstallationMeta[] {
  const raw = preload?.adminInstallations ?? preload?.installations;
  if (raw instanceof Map) return [...raw.values()].filter(isInstallationMeta);
  if (Array.isArray(raw)) return raw.filter(isInstallationMeta);
  if (raw && typeof raw === "object") {
    return Object.values(raw).filter(isInstallationMeta);
  }
  return [];
}

function isInstallationMeta(value: unknown): value is GitHubInstallationMeta {
  return Boolean(value && typeof value === "object" && "account" in value);
}

function sameAccount(left: GitHubAccount | undefined, right: GitHubAccount): boolean {
  if (!left) return false;
  if (typeof left.id === "number" && typeof right.id === "number") return left.id === right.id;
  return Boolean(
    left.login && right.login && left.login === right.login && left.type === right.type,
  );
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : undefined;
  }
  return typeof value === "number" ? value : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function fromResponse(res: Response, op: string) {
  if (res.status === 401 || res.status === 403) {
    return makeError("auth_failed", `github ${op}: ${res.status}`, "github");
  }
  if (res.status === 429) return makeError("rate_limited", `github ${op}: 429`, "github");
  if (res.status === 404) return makeError("not_found", `github ${op}: 404`, "github");
  if (res.status >= 500) {
    return makeError("provider_error", `github ${op}: ${res.status}`, "github");
  }
  return makeError("provider_error", `github ${op}: ${res.status}`, "github", {
    retryable: false,
  });
}
