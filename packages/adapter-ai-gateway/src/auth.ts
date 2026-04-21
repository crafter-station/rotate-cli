import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const VERCEL_BASE = process.env.VERCEL_API_URL ?? "https://api.vercel.com";

export const vercelAiGatewayAuthDefinition: AuthDefinition = {
  name: "vercel-ai-gateway",
  displayName: "Vercel AI Gateway",
  envVars: ["VERCEL_TOKEN"],
  setupUrl: "https://vercel.com/account/tokens",
  notes: [
    "Shares VERCEL_TOKEN with adapter-vercel-token — same credential.",
    "AI Gateway keys themselves (vck_*) are dashboard-only today; rotate-cli uses the underlying Vercel access token to list/rotate.",
  ],
  methods: [
    {
      id: "paste-access-token-key",
      label: "Paste Vercel access token",
      description: "Create a Vercel access token and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Vercel access tokens: https://vercel.com/account/tokens\nCreate an access token, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Vercel access token",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitVercelAiGatewayKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.VERCEL_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "VERCEL_TOKEN", token: envToken };
    }
    const stored = readStoredAuthContext("vercel-ai-gateway");
    if (stored) return stored;
    throw new Error(
      "vercel-ai-gateway auth unavailable: set VERCEL_TOKEN or run `rotate auth login vercel-ai-gateway`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Vercel access token");
    return submitVercelAiGatewayKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyVercelAiGatewayAuth(ctx);
  },
};

async function submitVercelAiGatewayKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("vercel-ai-gateway auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "VERCEL_TOKEN", token };
  await verifyVercelAiGatewayAuth(ctx);
  const path = writeStoredCredential("vercel-ai-gateway", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyVercelAiGatewayAuth(ctx: AuthContext): Promise<void> {
  const res = await request(`${VERCEL_BASE}/v2/user`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`vercel-ai-gateway verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`vercel-ai-gateway verify failed: ${res.status}`);
  }
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
