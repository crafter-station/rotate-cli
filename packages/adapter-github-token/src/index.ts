import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { makeError } from "@rotate/core";
import type {
  Adapter,
  AuthContext,
  RotationResult,
  RotationSpec,
  Secret,
} from "@rotate/core/types";

const GITHUB_BASE = process.env.GITHUB_API_URL ?? "https://api.github.com";

interface GitHubInstallationToken {
  token: string;
  expires_at: string;
  permissions?: Record<string, string>;
  repositories?: Array<{ id: number; name: string; full_name?: string }>;
  repository_selection?: string;
}

export const githubTokenAdapter: Adapter = {
  name: "github",

  async auth(): Promise<AuthContext> {
    const ghToken = readGhToken();
    if (ghToken) {
      return {
        kind: "cli-piggyback",
        tool: "gh",
        tokenPath: firstExistingGhPath(),
        token: ghToken,
      };
    }
    const envToken = process.env.GITHUB_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "GITHUB_TOKEN", token: envToken };
    }
    throw new Error("github auth unavailable: run `gh auth login` or set GITHUB_TOKEN");
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
};

export default githubTokenAdapter;

function readGhToken(): string | null {
  try {
    const output = execFileSync("gh", ["auth", "token"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return output.length > 0 ? output : null;
  } catch {
    return null;
  }
}

function firstExistingGhPath(): string | undefined {
  for (const path of ghAuthPaths()) {
    if (existsSync(path)) return path;
  }
  return undefined;
}

function ghAuthPaths(): string[] {
  const home = homedir();
  return [
    join(home, ".config", "gh", "hosts.yml"),
    join(home, ".github", "hosts.yml"),
    join(home, ".config", "github", "hosts.yml"),
  ];
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

function tokenId(token: string, installationId: string): string {
  return `github/installation/${installationId}/${token.slice(-8)}`;
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
