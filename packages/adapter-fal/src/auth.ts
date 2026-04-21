import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const FAL_API_BASE = process.env.FAL_API_URL ?? "https://api.fal.ai/v1";

export const falAuthDefinition: AuthDefinition = {
  name: "fal",
  displayName: "fal.ai",
  envVars: ["FAL_ADMIN_KEY"],
  setupUrl: "https://fal.ai/dashboard/keys",
  notes: ["Admin-scoped key. The default key type will NOT work — check the Admin scope."],
  methods: [
    {
      id: "paste-admin-key",
      label: "Paste fal.ai admin key",
      description: "Create an Admin-scoped key in fal.ai and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "fal.ai keys: https://fal.ai/dashboard/keys\nCreate an Admin-scoped key. The default key type will not work.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste fal.ai admin key",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitFalKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.FAL_ADMIN_KEY;
    if (envToken) {
      return { kind: "env", varName: "FAL_ADMIN_KEY", token: envToken };
    }
    const stored = readStoredAuthContext("fal");
    if (stored) return stored;
    throw new Error("fal auth unavailable: set FAL_ADMIN_KEY or run `rotate auth login fal`");
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste fal.ai admin key");
    return submitFalKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyFalAuth(ctx);
  },
};

async function submitFalKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("fal auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "FAL_ADMIN_KEY", token };
  await verifyFalAuth(ctx);
  const path = writeStoredCredential("fal", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyFalAuth(ctx: AuthContext): Promise<void> {
  const res = await request(`${FAL_API_BASE}/keys`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`fal verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`fal verify failed: ${res.status}`);
  }
}

function authHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Key ${token}`,
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
