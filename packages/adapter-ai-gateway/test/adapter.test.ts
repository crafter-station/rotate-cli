import { afterEach, beforeEach, describe, expect, test } from "bun:test";
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
});

afterEach(() => {
  global.fetch = originalFetch;
});

const mockCtx: AuthContext = { kind: "env", varName: "VERCEL_TOKEN", token: "vercel_test" };

describe("adapter-ai-gateway.create", () => {
  test("calls Vercel API and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            token: {
              id: "tok_new",
              name: "ai-gateway-rotated-123",
              type: "oauth2-token",
              createdAt: 1632816536002,
              expiresAt: 1632902936002,
            },
            bearerToken: "vck_new_token",
          }),
          { status: 200 },
        ),
    );
    const result = await aiGatewayAdapter.create(
      {
        secretId: "main",
        adapter: "vercel-ai-gateway",
        metadata: { teamId: "team_x", name: "ai-gateway-rotated-123" },
      },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.id).toBe("tok_new");
    expect(result.data?.provider).toBe("vercel-ai-gateway");
    expect(result.data?.value).toBe("vck_new_token");
    expect(result.data?.metadata.token_id).toBe("tok_new");
    expect(result.data?.metadata.teamId).toBe("team_x");
    expect(result.data?.createdAt).toBe("2021-09-28T08:08:56.002Z");
    expect(result.data?.expiresAt).toBe("2021-09-29T08:08:56.002Z");
    expect(calls[0]?.url).toContain("/v3/user/tokens");
    expect(calls[0]?.url).toContain("teamId=team_x");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await aiGatewayAdapter.create(
      { secretId: "main", adapter: "vercel-ai-gateway", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-ai-gateway.verify", () => {
  test("calls /v2/user with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ user: { id: "usr_x" } }), { status: 200 }));
    const secret: Secret = {
      id: "tok_new",
      provider: "vercel-ai-gateway",
      value: "vck_new_token",
      metadata: {},
      createdAt: new Date().toISOString(),
    };
    const result = await aiGatewayAdapter.verify(secret, mockCtx);
    expect(result.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/v2\/user$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer vck_new_token",
    );
  });
});

describe("adapter-ai-gateway.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "tok_old",
      provider: "vercel-ai-gateway",
      value: "vck_old_token",
      metadata: { token_id: "tok_old" },
      createdAt: new Date().toISOString(),
    };
    const result = await aiGatewayAdapter.revoke(secret, mockCtx);
    expect(result.ok).toBe(true);
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
