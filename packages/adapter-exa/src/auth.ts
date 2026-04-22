import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const EXA_API_KEYS_BASE =
  process.env.EXA_API_KEYS_URL ?? "https://admin-api.exa.ai/team-management/api-keys";

export const exaAuthDefinition: AuthDefinition = {
  name: "exa",
  displayName: "Exa",
  envVars: ["EXA_API_KEY"],
  setupUrl: "https://dashboard.exa.ai/api-keys",
  notes: [
    "Requires an Exa service/admin API key with Team Management API access.",
    "Standard search-only keys may not be sufficient for rotation.",
  ],
  methods: [
    {
      id: "paste-service-key",
      label: "Paste Exa service API key",
      description: "Create an Exa service/admin API key and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Exa API keys: https://dashboard.exa.ai/api-keys\nUse a service/admin key that can access Team Management endpoints.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Exa service/admin API key",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitExaKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.EXA_API_KEY;
    if (envToken) {
      return { kind: "env", varName: "EXA_API_KEY", token: envToken };
    }
    const stored = readStoredAuthContext("exa");
    if (stored) return stored;
    throw new Error("exa auth unavailable: set EXA_API_KEY or run `rotate auth login exa`");
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Exa service/admin API key");
    return submitExaKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyExaAuth(ctx);
  },
};

async function submitExaKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("exa auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "EXA_API_KEY", token };
  await verifyExaAuth(ctx);
  const path = writeStoredCredential("exa", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyExaAuth(ctx: AuthContext): Promise<void> {
  const res = await request(EXA_API_KEYS_BASE, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`exa verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`exa verify failed: ${res.status}`);
  }
}

function authHeaders(token: string): Record<string, string> {
  return {
    "x-api-key": token,
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
