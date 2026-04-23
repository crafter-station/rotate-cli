import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getAuthDefinition } from "@rotate/core";
import { registerAdapter } from "@rotate/core/registry";
import type { AuthContext, Secret } from "@rotate/core/types";
import { aiGatewayAdapter } from "../src/index.ts";

type FetchFn = typeof fetch;

const originalFetch = global.fetch;
let calls: Array<{ url: string; init?: RequestInit }> = [];

function mockFetch(responder: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  global.fetch = ((url: RequestInfo | URL, init?: RequestInit) => {
    const u = typeof url === "string" ? url : url.toString();
    calls.push({ url: u, init });
    return Promise.resolve(responder(u, init));
  }) as FetchFn;
}

beforeEach(() => {
  calls = [];
  delete process.env.VERCEL_TOKEN;
});

afterEach(() => {
  global.fetch = originalFetch;
  delete process.env.VERCEL_TOKEN;
});

const mockCtx: AuthContext = { kind: "env", varName: "VERCEL_TOKEN", token: "vercel_test" };

function mockIO(pasted: string, confirm = true): import("@rotate/core/types").PromptIO {
  return {
    isInteractive: true,
    async promptSecret() {
      return pasted;
    },
    async confirm() {
      return confirm;
    },
    async select<T>() {
      return undefined as unknown as T;
    },
    note(_: string) {},
    async close() {},
  } as unknown as import("@rotate/core/types").PromptIO;
}

describe("adapter-ai-gateway.create (manual-assist)", () => {
  test("prompts for new vck_* key and returns it", async () => {
    const io = mockIO("vck_abcdefghijklmnopqrstuvwxyz0123456789abcd");
    const result = await aiGatewayAdapter.create(
      { secretId: "main", adapter: "vercel-ai-gateway", metadata: {}, io },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toMatch(/^vck_/);
    expect(result.data?.metadata.manual_assist).toBe("true");
  });

  test("rejects values that do not match vck_* format", async () => {
    const io = mockIO("not-a-vck-key");
    const result = await aiGatewayAdapter.create(
      { secretId: "main", adapter: "vercel-ai-gateway", metadata: {}, io },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_spec");
  });

  test("without interactive IO returns unsupported", async () => {
    const result = await aiGatewayAdapter.create(
      { secretId: "main", adapter: "vercel-ai-gateway", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("unsupported");
  });
});

describe("adapter-ai-gateway.verify", () => {
  test("calls AI Gateway /v1/models with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ data: [] }), { status: 200 }));
    const secret: Secret = {
      id: "tok_new",
      provider: "vercel-ai-gateway",
      value: "vck_new_token",
      metadata: {},
      createdAt: new Date().toISOString(),
    };
    const result = await aiGatewayAdapter.verify(secret, mockCtx);
    expect(result.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/v1\/models$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer vck_new_token",
    );
  });
});

describe("adapter-ai-gateway.revoke (manual-assist)", () => {
  test("succeeds when user confirms", async () => {
    const io = mockIO("", true);
    const secret: Secret = {
      id: "tok_old",
      provider: "vercel-ai-gateway",
      value: "vck_old_token",
      metadata: { token_id: "tok_old" },
      createdAt: new Date().toISOString(),
    };
    const result = await aiGatewayAdapter.revoke(secret, mockCtx, { io });
    expect(result.ok).toBe(true);
  });
});

describe("adapter-ai-gateway.auth", () => {
  test("resolves env auth through shared auth registry", async () => {
    if (!getAuthDefinition("vercel-ai-gateway")) {
      registerAdapter(aiGatewayAdapter);
    }
    process.env.VERCEL_TOKEN = "test-token";
    const ctx = await aiGatewayAdapter.auth();
    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("test-token");
  });

  test("registers auth definition with the adapter", () => {
    if (!getAuthDefinition("vercel-ai-gateway")) {
      registerAdapter(aiGatewayAdapter);
    }
    expect(getAuthDefinition("vercel-ai-gateway")?.displayName).toBe("Vercel AI Gateway");
  });
});

describe("adapter-ai-gateway.ownedBy", () => {
  test("returns self for a live key when admin has exactly one Vercel team", async () => {
    mockFetch((url, init) => {
      if (url === "https://ai-gateway.vercel.sh/v1/models") {
        expect((init?.headers as Record<string, string>)?.Authorization).toBe(
          `Bearer ${validAiGatewayKey()}`,
        );
        return new Response(JSON.stringify({ data: [{ id: "openai/gpt-5.4" }] }), {
          status: 200,
        });
      }
      if (url === "https://api.vercel.com/v2/teams") {
        expect((init?.headers as Record<string, string>)?.Authorization).toBe("Bearer vercel_test");
        return new Response(
          JSON.stringify({
            teams: [{ id: "team_one", slug: "one", membership: { role: "OWNER" } }],
          }),
          { status: 200 },
        );
      }
      return new Response("not found", { status: 404 });
    });

    const result = await aiGatewayAdapter.ownedBy?.(validAiGatewayKey(), mockCtx);

    expect(result?.verdict).toBe("self");
    expect(result?.scope).toBe("team");
    expect(result?.teamRole).toBe("admin");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.confidence).toBe("medium");
    expect(result?.strategy).toBe("format-decode");
    expect(calls.map((call) => call.url)).toEqual([
      "https://ai-gateway.vercel.sh/v1/models",
      "https://api.vercel.com/v2/teams",
    ]);
  });

  test("returns other for an OIDC token owned by a different team", async () => {
    mockFetch((url) => {
      if (url === "https://api.vercel.com/v2/teams") {
        return new Response(
          JSON.stringify({
            teams: [{ id: "team_admin", slug: "admin", membership: { role: "MEMBER" } }],
          }),
          { status: 200 },
        );
      }
      return new Response("not found", { status: 404 });
    });

    const result = await aiGatewayAdapter.ownedBy?.(oidcToken("team_elsewhere"), mockCtx);

    expect(result?.verdict).toBe("other");
    expect(result?.scope).toBe("team");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("high");
    expect(result?.strategy).toBe("format-decode");
    expect(calls.map((call) => call.url)).toEqual(["https://api.vercel.com/v2/teams"]);
  });

  test("returns unknown on a revoked key", async () => {
    mockFetch((url) => {
      if (url === "https://ai-gateway.vercel.sh/v1/models") {
        return new Response("unauthorized", { status: 401 });
      }
      return new Response("not found", { status: 404 });
    });

    const result = await aiGatewayAdapter.ownedBy?.(validAiGatewayKey(), mockCtx);

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
    expect(result?.evidence).toBe("AI Gateway key revoked or invalid");
    expect(calls).toHaveLength(1);
  });

  test("returns unknown on a network error", async () => {
    global.fetch = ((url: RequestInfo | URL, init?: RequestInit) => {
      const u = typeof url === "string" ? url : url.toString();
      calls.push({ url: u, init });
      throw new Error("socket closed");
    }) as FetchFn;

    const result = await aiGatewayAdapter.ownedBy?.(validAiGatewayKey(), mockCtx);

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.evidence).toBe("AI Gateway ownership check network error");
  });
});

function validAiGatewayKey(): string {
  return "vck_abcdefghijklmnopqrstuvwxyzABCDEF0123456789";
}

function oidcToken(ownerId: string): string {
  return [
    base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" })),
    base64Url(JSON.stringify({ owner_id: ownerId })),
    "signature",
  ].join(".");
}

function base64Url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}
