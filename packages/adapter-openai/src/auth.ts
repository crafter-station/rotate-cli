import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const OPENAI_ADMIN_KEYS_BASE =
  process.env.OPENAI_ADMIN_KEYS_URL ?? "https://api.openai.com/v1/organization/admin_api_keys";

export const openaiAuthDefinition: AuthDefinition = {
  name: "openai",
  displayName: "OpenAI",
  envVars: ["OPENAI_ADMIN_KEY"],
  setupUrl: "https://platform.openai.com/settings/organization/admin-keys",
  notes: ["Requires an OpenAI admin key, not a standard project API key."],
  methods: [
    {
      id: "paste-admin-key",
      label: "Paste admin key",
      description: "Create an admin key in OpenAI and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "OpenAI admin keys: https://platform.openai.com/settings/organization/admin-keys\nCreate an admin key, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste OpenAI admin key",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitOpenAIKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.OPENAI_ADMIN_KEY;
    if (envToken) {
      return { kind: "env", varName: "OPENAI_ADMIN_KEY", token: envToken };
    }
    const stored = readStoredAuthContext("openai");
    if (stored) return stored;
    throw new Error(
      "openai auth unavailable: set OPENAI_ADMIN_KEY or run `rotate auth login openai`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste OpenAI admin key");
    return submitOpenAIKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyOpenAIAuth(ctx);
  },
};

async function submitOpenAIKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("openai auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "OPENAI_ADMIN_KEY", token };
  await verifyOpenAIAuth(ctx);
  const path = writeStoredCredential("openai", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyOpenAIAuth(ctx: AuthContext): Promise<void> {
  const res = await request(`${OPENAI_ADMIN_KEYS_BASE}?limit=1`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`openai verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`openai verify failed: ${res.status}`);
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
