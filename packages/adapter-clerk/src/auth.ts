import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const CLERK_PLAPI_BASE = process.env.CLERK_PLAPI_URL ?? "https://api.clerk.com";

export const clerkAuthDefinition: AuthDefinition = {
  name: "clerk",
  displayName: "Clerk",
  envVars: ["CLERK_PLAPI_TOKEN"],
  setupUrl: "https://dashboard.clerk.com/last-active?path=platform-api",
  notes: ["Requires a Platform API token (ak_* or plapi_*)."],
  methods: [
    {
      id: "paste-platform-api-key",
      label: "Paste Clerk Platform API token",
      description: "Create a Platform API token in Clerk and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Clerk Platform API tokens: https://dashboard.clerk.com/last-active?path=platform-api\nCreate a Platform API token, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Clerk Platform API token",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitClerkKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.CLERK_PLAPI_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "CLERK_PLAPI_TOKEN", token: envToken };
    }
    const stored = readStoredAuthContext("clerk");
    if (stored) return stored;
    throw new Error(
      "clerk auth unavailable: set CLERK_PLAPI_TOKEN or run `rotate auth login clerk`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Clerk Platform API token");
    return submitClerkKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyClerkAuth(ctx);
  },
};

async function submitClerkKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("clerk auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "CLERK_PLAPI_TOKEN", token };
  await verifyClerkAuth(ctx);
  const path = writeStoredCredential("clerk", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyClerkAuth(ctx: AuthContext): Promise<void> {
  const res = await request(`${CLERK_PLAPI_BASE}/v1/jwks`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`clerk verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`clerk verify failed: ${res.status}`);
  }
}

function authHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    "User-Agent": "rotate-cli/0.0.1",
  };
}

async function request(url: string, init: RequestInit): Promise<Response | Error> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
  }
}
