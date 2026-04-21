import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const NEON_BASE = process.env.NEON_API_URL ?? "https://console.neon.tech/api/v2";

export const neonAuthDefinition: AuthDefinition = {
  name: "neon",
  displayName: "Neon",
  envVars: ["NEON_API_KEY"],
  setupUrl: "https://console.neon.tech/app/settings/api-keys",
  notes: ["Neon API key (napi_*)."],
  methods: [
    {
      id: "paste-api-key",
      label: "Paste Neon API key",
      description: "Create an API key in Neon and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Neon API keys: https://console.neon.tech/app/settings/api-keys\nCreate an API key, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Neon API key",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitNeonKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.NEON_API_KEY;
    if (envToken) {
      return { kind: "env", varName: "NEON_API_KEY", token: envToken };
    }
    const stored = readStoredAuthContext("neon");
    if (stored) return stored;
    throw new Error("neon auth unavailable: set NEON_API_KEY or run `rotate auth login neon`");
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Neon API key");
    return submitNeonKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyNeonAuth(ctx);
  },
};

async function submitNeonKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("neon auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "NEON_API_KEY", token };
  await verifyNeonAuth(ctx);
  const path = writeStoredCredential("neon", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyNeonAuth(ctx: AuthContext): Promise<void> {
  const res = await request(`${NEON_BASE}/users/me`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`neon verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`neon verify failed: ${res.status}`);
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
