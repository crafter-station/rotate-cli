import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const ELEVENLABS_BASE = process.env.ELEVENLABS_API_URL ?? "https://api.elevenlabs.io";

export const elevenlabsAuthDefinition: AuthDefinition = {
  name: "elevenlabs",
  displayName: "ElevenLabs",
  envVars: ["ELEVENLABS_ADMIN_KEY"],
  setupUrl: "https://elevenlabs.io/app/settings/workspace/api-keys",
  notes: ["Workspace admin key. Requires a multi-seat plan (Creator or higher)."],
  methods: [
    {
      id: "paste-workspace-admin-key",
      label: "Paste ElevenLabs admin API key",
      description: "Create a workspace admin key in ElevenLabs and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "ElevenLabs API keys: https://elevenlabs.io/app/settings/workspace/api-keys\nCreate a workspace admin key on a multi-seat plan, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste ElevenLabs admin API key",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitElevenLabsKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.ELEVENLABS_ADMIN_KEY;
    if (envToken) {
      return { kind: "env", varName: "ELEVENLABS_ADMIN_KEY", token: envToken };
    }
    const stored = readStoredAuthContext("elevenlabs");
    if (stored) return stored;
    throw new Error(
      "elevenlabs auth unavailable: set ELEVENLABS_ADMIN_KEY or run `rotate auth login elevenlabs`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste ElevenLabs admin API key");
    return submitElevenLabsKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyElevenLabsAuth(ctx);
  },
};

async function submitElevenLabsKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("elevenlabs auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "ELEVENLABS_ADMIN_KEY", token };
  await verifyElevenLabsAuth(ctx);
  const path = writeStoredCredential("elevenlabs", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyElevenLabsAuth(ctx: AuthContext): Promise<void> {
  const res = await request(`${ELEVENLABS_BASE}/v1/user`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`elevenlabs verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`elevenlabs verify failed: ${res.status}`);
  }
}

function authHeaders(token: string): Record<string, string> {
  return {
    "xi-api-key": token,
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
