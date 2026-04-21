import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { neonAdapter } from "../src/index.ts";

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

const mockCtx: AuthContext = { kind: "env", varName: "NEON_API_KEY", token: "neon_test" };

describe("adapter-neon.create", () => {
  test("calls Neon API and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            id: 123,
            key: "napi_live_abc",
            project_id: "prj_x",
            created_at: "2026-04-21T10:00:00Z",
          }),
          { status: 200 },
        ),
    );
    const result = await neonAdapter.create(
      { secretId: "main", adapter: "neon", metadata: { project_id: "prj_x" } },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("napi_live_abc");
    expect(result.data?.metadata.key_id).toBe("123");
    expect(result.data?.metadata.project_id).toBe("prj_x");
    expect(calls[0]?.url).toContain("/projects/prj_x/api_keys");
  });

  test("missing project_id returns invalid_spec", async () => {
    const result = await neonAdapter.create(
      { secretId: "main", adapter: "neon", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_spec");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await neonAdapter.create(
      { secretId: "m", adapter: "neon", metadata: { project_id: "prj_x" } },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-neon.verify", () => {
  test("calls /users/me with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ id: "user_x" }), { status: 200 }));
    const secret: Secret = {
      id: "123",
      provider: "neon",
      value: "napi_live_abc",
      metadata: {},
      createdAt: new Date().toISOString(),
    };
    const r = await neonAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/users\/me$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer napi_live_abc",
    );
  });
});

describe("adapter-neon.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "123",
      provider: "neon",
      value: "napi_live_old",
      metadata: { project_id: "prj_x", key_id: "123" },
      createdAt: new Date().toISOString(),
    };
    const r = await neonAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
  });
});
