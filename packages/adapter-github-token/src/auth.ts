import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const GITHUB_BASE = githubBaseUrl();

export const githubTokenAuthDefinition: AuthDefinition = {
  name: "github-token",
  displayName: "GitHub",
  envVars: ["GITHUB_TOKEN"],
  setupUrl: "https://github.com/settings/tokens?type=beta",
  notes: [
    "A fine-grained PAT or GitHub App installation token.",
    "rotate-cli also accepts `gh auth token` output as a fallback.",
  ],
  methods: [
    {
      id: "paste-github-token-key",
      label: "Paste GitHub token",
      description: "Create a fine-grained PAT or GitHub App installation token and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "GitHub tokens: https://github.com/settings/tokens?type=beta\nCreate a fine-grained PAT or GitHub App installation token, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste GitHub token",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitGitHubKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.GITHUB_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "GITHUB_TOKEN", token: envToken };
    }
    const stored = readStoredAuthContext("github-token");
    if (stored) return stored;
    throw new Error(
      "github-token auth unavailable: set GITHUB_TOKEN or run `rotate auth login github-token`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste GitHub token");
    return submitGitHubKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyGitHubAuth(ctx);
  },
};

async function submitGitHubKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("github-token auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "GITHUB_TOKEN", token };
  await verifyGitHubAuth(ctx);
  const path = writeStoredCredential("github-token", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyGitHubAuth(ctx: AuthContext): Promise<void> {
  const userRes = await request(`${GITHUB_BASE}/user`, {
    headers: authHeaders(ctx.token),
  });
  if (userRes instanceof Error) {
    throw new Error(`github-token verify failed: ${userRes.message}`);
  }
  if (userRes.ok) return;

  const installationRes = await request(`${GITHUB_BASE}/installation/repositories?per_page=1`, {
    headers: authHeaders(ctx.token),
  });
  if (installationRes instanceof Error) {
    throw new Error(`github-token verify failed: ${installationRes.message}`);
  }
  if (!installationRes.ok) {
    throw new Error(`github-token verify failed: ${installationRes.status}`);
  }
}

function authHeaders(token: string): Record<string, string> {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    "User-Agent": "rotate-cli/0.0.1",
    "X-GitHub-Api-Version": "2026-03-10",
  };
}

function githubBaseUrl(): string {
  if (process.env.GITHUB_API_URL) return process.env.GITHUB_API_URL;
  const host = process.env.GH_HOST;
  if (!host) return "https://api.github.com";
  const normalized = host.replace(/^https?:\/\//, "").replace(/\/$/, "");
  if (normalized === "github.com") return "https://api.github.com";
  return `https://${normalized}/api/v3`;
}

async function request(url: string, init: RequestInit): Promise<Response | Error> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
  }
}
