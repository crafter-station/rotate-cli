import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const NEON_BASE = process.env.NEON_API_URL ?? "https://console.neon.tech/api/v2";

export const neonConnectionAuthDefinition: AuthDefinition = {
  name: "neon-connection",
  displayName: "Neon (connection strings)",
  envVars: ["NEON_API_KEY"],
  setupUrl: "https://console.neon.tech/app/settings/api-keys",
  notes: [
    "Rotates role passwords on Neon branches (produces new DATABASE_URL).",
    "Shares the NEON_API_KEY env var with adapter-neon — same credential.",
  ],
  methods: [
    {
      id: "paste-api-key",
      label: "Paste Neon API key",
      description: "Create a Neon API key and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Neon API keys: https://console.neon.tech/app/settings/api-keys\nVerify endpoint: GET https://console.neon.tech/api/v2/users/me",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Neon API key",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitNeonConnectionKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.NEON_API_KEY;
    if (envToken) {
      return { kind: "env", varName: "NEON_API_KEY", token: envToken };
    }
    const stored = readStoredAuthContext("neon-connection");
    if (stored) return stored;
    throw new Error(
      "neon-connection auth unavailable: set NEON_API_KEY or run `rotate auth login neon-connection`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Neon API key");
    return submitNeonConnectionKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyNeonConnectionAuth(ctx);
  },
};

async function submitNeonConnectionKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("neon-connection auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "NEON_API_KEY", token };
  await verifyNeonConnectionAuth(ctx);
  const path = writeStoredCredential("neon-connection", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyNeonConnectionAuth(ctx: AuthContext): Promise<void> {
  const res = await request(`${NEON_BASE}/users/me`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`neon-connection verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`neon-connection verify failed: ${res.status}`);
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
