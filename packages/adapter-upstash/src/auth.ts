import { readStoredAuthContext, writeStoredCredential } from "@rotate/core/auth-store";
import type { AuthContext, AuthDefinition, PromptAnswers, PromptIO } from "@rotate/core/types";

const UPSTASH_API_BASE = process.env.UPSTASH_API_URL ?? "https://api.upstash.com/v2";

export const upstashAuthDefinition: AuthDefinition = {
  name: "upstash",
  displayName: "Upstash",
  envVars: ["UPSTASH_EMAIL", "UPSTASH_API_KEY"],
  setupUrl: "https://console.upstash.com/account/api",
  notes: [
    "Upstash uses basic auth with account email and API key.",
    "Also powers adapter-vercel-kv because Vercel KV is Upstash Redis rebranded.",
    "Verify with GET https://api.upstash.com/v2/account using basic auth (email:key).",
  ],
  methods: [
    {
      id: "paste-api-key",
      label: "Paste API key",
      description: "Create an Upstash API key and paste it here",
      steps: [
        {
          kind: "note",
          message:
            "Upstash API keys: https://console.upstash.com/account/api\nCopy your account email and API key, then paste them below.",
        },
        {
          kind: "text",
          name: "email",
          message: "Upstash account email",
        },
        {
          kind: "password",
          name: "apiKey",
          message: "Paste Upstash API key",
        },
      ],
      async submit(answers: PromptAnswers, _io: PromptIO): Promise<AuthContext> {
        return submitUpstashKey(answers.email, answers.apiKey);
      },
    },
  ],

  async resolve(): Promise<AuthContext> {
    const email = process.env.UPSTASH_EMAIL;
    const apiKey = process.env.UPSTASH_API_KEY;
    if (email && apiKey) {
      return {
        kind: "env",
        varName: "UPSTASH_EMAIL,UPSTASH_API_KEY",
        token: authToken(email, apiKey),
      };
    }
    const stored = readStoredAuthContext("upstash");
    if (stored) return stored;
    throw new Error(
      "upstash auth unavailable: set UPSTASH_EMAIL and UPSTASH_API_KEY or run `rotate auth login upstash`",
    );
  },

  async login(io: PromptIO): Promise<AuthContext> {
    const email = await io.promptLine("Upstash account email");
    const apiKey = await io.promptSecret("Paste Upstash API key");
    return submitUpstashKey(email, apiKey);
  },

  async verify(ctx: AuthContext): Promise<void> {
    await verifyUpstashAuth(ctx);
  },
};

async function submitUpstashKey(rawEmail: unknown, rawApiKey: unknown): Promise<AuthContext> {
  const email = typeof rawEmail === "string" ? rawEmail.trim() : "";
  const apiKey = typeof rawApiKey === "string" ? rawApiKey.trim() : "";
  if (!email) {
    throw new Error("upstash auth unavailable: account email was empty");
  }
  if (!apiKey) {
    throw new Error("upstash auth unavailable: pasted key was empty");
  }
  const token = authToken(email, apiKey);
  const ctx: AuthContext = { kind: "env", varName: "UPSTASH_EMAIL,UPSTASH_API_KEY", token };
  await verifyUpstashAuth(ctx);
  const path = writeStoredCredential("upstash", token);
  return { kind: "encrypted-file", path, token };
}

export async function verifyUpstashAuth(ctx: AuthContext): Promise<void> {
  const res = await request(`${UPSTASH_API_BASE}/account`, {
    headers: authHeaders(ctx.token),
  });
  if (res instanceof Error) {
    throw new Error(`upstash verify failed: ${res.message}`);
  }
  if (!res.ok) {
    throw new Error(`upstash verify failed: ${res.status}`);
  }
}

function authHeaders(token: string): Record<string, string> {
  const [email, apiKey] = splitAuthToken(token);
  return {
    Authorization: `Basic ${Buffer.from(authToken(email, apiKey)).toString("base64")}`,
    "Content-Type": "application/json",
    "User-Agent": "rotate-cli/0.0.1",
  };
}

function authToken(email: string, apiKey: string): string {
  return `${email}:${apiKey}`;
}

function splitAuthToken(token: string): [string, string] {
  const separator = token.indexOf(":");
  if (separator === -1) return ["", token];
  return [token.slice(0, separator), token.slice(separator + 1)];
}

async function request(url: string, init: RequestInit): Promise<Response | Error> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
  }
}
