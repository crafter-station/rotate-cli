import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const ANTHROPIC_BASE = process.env.ANTHROPIC_API_URL ?? "https://api.anthropic.com";
const API_KEYS_PATH = "/v1/organizations/api_keys";
const ANTHROPIC_VERSION = "2023-06-01";

export const anthropicAuthDefinition: AuthDefinition = {
  name: "anthropic",
  displayName: "Anthropic",
  envVars: ["ANTHROPIC_ADMIN_KEY"],
  setupUrl: "https://platform.claude.com/settings/admin-keys",
  notes: ["Requires an Anthropic admin key, not a standard API key."],
  methods: [
    {
      id: "paste-admin-key",
      label: "Paste admin key",
      description: "Create an admin key in Claude Console and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Anthropic admin keys: https://platform.claude.com/settings/admin-keys\nCreate an admin key, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Anthropic admin key",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitAnthropicKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.ANTHROPIC_ADMIN_KEY;
    if (envToken) {
      return { kind: "env", varName: "ANTHROPIC_ADMIN_KEY", token: envToken };
    }
    const stored = readStoredAuthContext("anthropic");
    if (stored) return stored;
    throw new Error(
      "anthropic auth unavailable: set ANTHROPIC_ADMIN_KEY or run `rotate auth login anthropic`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Anthropic admin key");
    return submitAnthropicKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyAnthropicAuth(ctx);
  },
};

async function submitAnthropicKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("anthropic auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "ANTHROPIC_ADMIN_KEY", token };
  await verifyAnthropicAuth(ctx);
  const path = writeStoredCredential("anthropic", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyAnthropicAuth(ctx: AuthContext): Promise<void> {
  const res = await request(`${ANTHROPIC_BASE}${API_KEYS_PATH}?limit=1`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`anthropic verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`anthropic verify failed: ${res.status}`);
  }
}

function authHeaders(token: string): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "anthropic-version": ANTHROPIC_VERSION,
    "x-api-key": token,
  };
}

async function request(url: string, init: RequestInit): Promise<Response | Error> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
  }
}
