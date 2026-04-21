import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { falAdapter } from "../src/index.ts";

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

const mockCtx: AuthContext = { kind: "env", varName: "FAL_ADMIN_KEY", token: "admin_old" };

describe("adapter-fal.create", () => {
  test("calls fal.ai API and returns Secret", async () => {
    mockFetch((url) => {
      if (url.endsWith("/keys")) {
        return new Response(
          JSON.stringify({
            key_id: "key_new",
            key_secret: "sk_live_new",
            key: "key_new:sk_live_new",
          }),
          { status: 201 },
        );
      }
      return new Response(
        JSON.stringify({
          keys: [
            {
              key_id: "key_new",
              alias: "Production",
              scope: "API",
              created_at: "2026-04-20T00:00:00.000Z",
            },
          ],
        }),
        { status: 200 },
      );
    });
    const result = await falAdapter.create(
      { secretId: "main", adapter: "fal-ai", metadata: { alias: "Production" } },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("key_new:sk_live_new");
    expect(result.data?.metadata.key_id).toBe("key_new");
    expect(result.data?.metadata.alias).toBe("Production");
    expect(result.data?.createdAt).toBe("2026-04-20T00:00:00.000Z");
    expect(calls[0]?.url).toContain("/v1/keys");
    expect(calls[0]?.init?.method).toBe("POST");
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Key admin_old",
    );
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await falAdapter.create(
      { secretId: "m", adapter: "fal-ai", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-fal.verify", () => {
  test("calls models usage with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ total_requests: 0 }), { status: 200 }));
    const secret: Secret = {
      id: "key_new",
      provider: "fal-ai",
      value: "key_new:sk_live_new",
      metadata: {},
      createdAt: new Date().toISOString(),
    };
    const r = await falAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/v1\/models\/usage$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Key key_new:sk_live_new",
    );
  });
});

describe("adapter-fal.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "key_old",
      provider: "fal-ai",
      value: "key_old:sk_live_old",
      metadata: { key_id: "key_old" },
      createdAt: new Date().toISOString(),
    };
    const r = await falAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
  });
});
