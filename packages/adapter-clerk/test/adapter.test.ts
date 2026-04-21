import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { clerkAdapter } from "../src/index.ts";

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

const mockCtx: AuthContext = { kind: "env", varName: "CLERK_PLAPI_TOKEN", token: "plapi_test" };

describe("adapter-clerk.create", () => {
  test("calls PLAPI and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            id: "key_new",
            secret: "sk_live_abc",
            instance_id: "ins_x",
            created_at: 100,
          }),
          { status: 201 },
        ),
    );
    const result = await clerkAdapter.create(
      { secretId: "main", adapter: "clerk", metadata: { instance_id: "ins_x" } },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("sk_live_abc");
    expect(result.data?.metadata.key_id).toBe("key_new");
    expect(calls[0]?.url).toContain("/v1/instances/ins_x/api_keys");
  });

  test("missing instance_id returns invalid_spec", async () => {
    const result = await clerkAdapter.create(
      { secretId: "main", adapter: "clerk", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_spec");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await clerkAdapter.create(
      { secretId: "m", adapter: "clerk", metadata: { instance_id: "ins_x" } },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-clerk.verify", () => {
  test("calls /v1/me with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ id: "me" }), { status: 200 }));
    const secret: Secret = {
      id: "key_new",
      provider: "clerk",
      value: "sk_live_abc",
      metadata: {},
      createdAt: new Date().toISOString(),
    };
    const r = await clerkAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/v1\/me$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer sk_live_abc",
    );
  });
});

describe("adapter-clerk.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "key_old",
      provider: "clerk",
      value: "sk_live_old",
      metadata: { instance_id: "ins_x", key_id: "key_old" },
      createdAt: new Date().toISOString(),
    };
    const r = await clerkAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
  });
});
