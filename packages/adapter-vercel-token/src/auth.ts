import { existsSync, readFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const VERCEL_BASE = process.env.VERCEL_API_URL ?? "https://api.vercel.com";

export const vercelTokenAuthDefinition: AuthDefinition = {
  name: "vercel-token",
  displayName: "Vercel",
  envVars: ["VERCEL_TOKEN"],
  setupUrl: "https://vercel.com/account/tokens",
  notes: [
    "A personal or team access token.",
    "rotate-cli also accepts the CLI's own auth.json (~/Library/Application Support/com.vercel.cli/auth.json) as a fallback.",
  ],
  methods: [
    {
      id: "paste-access-key",
      label: "Paste Vercel access token",
      description: "Create a personal or team access token in Vercel and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Vercel access tokens: https://vercel.com/account/tokens\nCreate a personal or team access token, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Vercel access token",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitVercelKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.VERCEL_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "VERCEL_TOKEN", token: envToken };
    }
    const stored = readStoredAuthContext("vercel-token");
    if (stored) return stored;
    const cli = readVercelCliAuthContext();
    if (cli) return cli;
    throw new Error(
      "vercel-token auth unavailable: set VERCEL_TOKEN, run `rotate auth login vercel-token`, or run `vercel login`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Vercel access token");
    return submitVercelKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyVercelAuth(ctx);
  },
};

async function submitVercelKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("vercel-token auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "VERCEL_TOKEN", token };
  await verifyVercelAuth(ctx);
  const path = writeStoredCredential("vercel-token", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyVercelAuth(ctx: AuthContext): Promise<void> {
  const res = await request(`${VERCEL_BASE}/v2/user`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`vercel-token verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`vercel-token verify failed: ${res.status}`);
  }
}

function readVercelCliAuthContext(): AuthContext | undefined {
  for (const path of candidateAuthPaths()) {
    if (!existsSync(path)) continue;
    try {
      const data = JSON.parse(readFileSync(path, "utf8")) as { token?: string };
      if (data.token) {
        return { kind: "cli-piggyback", tool: "vercel", tokenPath: path, token: data.token };
      }
    } catch {}
  }
  return undefined;
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
