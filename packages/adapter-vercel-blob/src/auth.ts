import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const VERCEL_BASE = process.env.VERCEL_API_URL ?? "https://api.vercel.com";

export const vercelBlobAuthDefinition: AuthDefinition = {
  name: "vercel-blob",
  displayName: "Vercel Blob",
  envVars: ["BLOB_READ_WRITE_TOKEN", "BLOB_READ_ONLY_TOKEN", "BLOB_STORE_ID", "VERCEL_TOKEN"],
  setupUrl: "https://vercel.com/account/tokens",
  notes: [
    "Uses VERCEL_TOKEN for management auth; Blob tokens are the secrets being rotated.",
    "Create a Vercel access token that can read the target team or account storage stores.",
  ],
  methods: [
    {
      id: "paste-vercel-access-token",
      label: "Paste Vercel access token",
      description: "Create a Vercel access token and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Vercel access tokens: https://vercel.com/account/tokens\nCreate an access token that can read Vercel Blob stores, then paste it below.",
        },
        {
          kind: "password",
          name: "token",
          message: "Paste Vercel access token",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitVercelToken(answers.token);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const envToken = process.env.VERCEL_TOKEN;
    if (envToken) {
      return { kind: "env", varName: "VERCEL_TOKEN", token: envToken };
    }
    const stored = readStoredAuthContext("vercel-blob");
    if (stored) return stored;
    throw new Error(
      "vercel-blob auth unavailable: set VERCEL_TOKEN or run `rotate auth login vercel-blob`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const token = await io.promptSecret("Paste Vercel access token");
    return submitVercelToken(token);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyVercelBlobAuth(ctx);
  },
};

async function submitVercelToken(rawToken: unknown): Promise<AuthContext> {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  if (!token) {
    throw new Error("vercel-blob auth unavailable: pasted token was empty");
  }
  const ctx: AuthContext = { kind: "env", varName: "VERCEL_TOKEN", token };
  await verifyVercelBlobAuth(ctx);
  const path = writeStoredCredential("vercel-blob", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyVercelBlobAuth(ctx: AuthContext): Promise<void> {
  const res = await request(`${VERCEL_BASE}/v2/user`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`vercel-blob verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`vercel-blob verify failed: ${res.status}`);
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
