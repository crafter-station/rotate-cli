import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { vercelTokenAdapter } from "../src/index.ts";

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

const mockCtx: AuthContext = { kind: "env", varName: "VERCEL_TOKEN", token: "verc_test" };

describe("adapter-vercel-token.create", () => {
  test("calls Vercel API and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            token: {
              id: "tok_new",
              name: "rotate-cli-main",
              type: "oauth2-token",
              createdAt: 1632816536002,
              expiresAt: 1632902936002,
            },
            bearerToken: "vercel_new_token",
          }),
          { status: 200 },
        ),
    );
    const result = await vercelTokenAdapter.create(
      {
        secretId: "main",
        adapter: "vercel-token",
        metadata: { team_id: "team_x", name: "rotate-cli-main" },
      },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("vercel_new_token");
    expect(result.data?.metadata.token_id).toBe("tok_new");
    expect(result.data?.metadata.team_id).toBe("team_x");
    expect(result.data?.expiresAt).toBe("2021-09-29T08:08:56.002Z");
    expect(calls[0]?.url).toContain("/v3/user/tokens");
    expect(calls[0]?.url).toContain("teamId=team_x");
  });

  test("invalid expires_at returns invalid_spec", async () => {
    const result = await vercelTokenAdapter.create(
      {
        secretId: "main",
        adapter: "vercel-token",
        metadata: { expires_at: "tomorrow" },
      },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_spec");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await vercelTokenAdapter.create(
      { secretId: "m", adapter: "vercel-token", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-vercel-token.verify", () => {
  test("calls /v2/user with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ user: { id: "usr_x" } }), { status: 200 }));
    const secret: Secret = {
      id: "tok_new",
      provider: "vercel-token",
      value: "vercel_new_token",
      metadata: {},
      createdAt: new Date().toISOString(),
    };
    const r = await vercelTokenAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/v2\/user$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer vercel_new_token",
    );
  });
});

describe("adapter-vercel-token.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "tok_old",
      provider: "vercel-token",
      value: "vercel_old_token",
      metadata: { token_id: "tok_old" },
      createdAt: new Date().toISOString(),
    };
    const r = await vercelTokenAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
  });
});
