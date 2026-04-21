import {
  readStoredAuthContext,
  writeStoredCredential,
} from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const RESEND_API_KEYS_BASE = process.env.RESEND_API_KEYS_URL ?? "https://api.resend.com/api-keys";

export const resendAuthDefinition: AuthDefinition = {
  name: "resend",
  displayName: "Resend",
  envVars: ["RESEND_API_KEY"],
  setupUrl: "https://resend.com/api-keys?new=true",
  notes: ["Requires a Full access API key. Sending access keys are not sufficient."],
  methods: [
    {
      id: "paste-full-access-key",
      label: "Paste full access API key",
      description: "Create a Full access key in Resend and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Resend API keys: https://resend.com/api-keys?new=true\nCreate a Full access key, not a Sending access key, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Resend full access API key",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitResendKey(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.RESEND_API_KEY;
    if (envToken) {
      return { kind: "env", varName: "RESEND_API_KEY", token: envToken };
    }
    const stored = readStoredAuthContext("resend");
    if (stored) return stored;
    throw new Error("resend auth unavailable: set RESEND_API_KEY or run `rotate auth login resend`");
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Resend full access API key");
    return submitResendKey(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyResendAuth(ctx);
  },
};

async function submitResendKey(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("resend auth unavailable: pasted key was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "RESEND_API_KEY", token };
  await verifyResendAuth(ctx);
  const path = writeStoredCredential("resend", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyResendAuth(ctx: AuthContext): Promise<void> {
  const res = await request(RESEND_API_KEYS_BASE, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`resend verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`resend verify failed: ${res.status}`);
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
