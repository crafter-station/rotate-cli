import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getAuthDefinition, registerAdapter } from "@rotate/core";
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

describe("adapter-fal.auth", () => {
  beforeEach(() => {
    if (!getAuthDefinition("fal")) {
      registerAdapter(falAdapter);
    }
    delete process.env.FAL_ADMIN_KEY;
  });

  afterEach(() => {
    delete process.env.FAL_ADMIN_KEY;
  });

  test("resolves env auth through shared auth registry", async () => {
    process.env.FAL_ADMIN_KEY = "test-token";
    const ctx = await falAdapter.auth();
    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("test-token");
  });

  test("registers auth definition with the adapter", () => {
    expect(getAuthDefinition("fal")?.displayName).toBe("fal.ai");
  });
});

describe("adapter-fal.ownedBy", () => {
  test("returns self when the key_id is in the admin list", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            keys: [{ key_id: "key_self", alias: "Production", scope: "API" }],
            has_more: false,
          }),
          { status: 200 },
        ),
    );

    const result = await falAdapter.ownedBy?.("key_self:sk_live_self", mockCtx);

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.confidence).toBe("medium");
    expect(result?.strategy).toBe("list-match");
    expect(result?.evidence).toContain("key_self");
    expect(calls[0]?.url).toContain("/v1/keys?limit=100&expand=creator_info");
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Key admin_old",
    );
  });

  test("returns other when the key_id is absent from a complete admin list", async () => {
    mockFetch(
      () =>
        new Response(JSON.stringify({ keys: [{ key_id: "key_self" }], has_more: false }), {
          status: 200,
        }),
    );

    const result = await falAdapter.ownedBy?.("key_elsewhere:sk_live_other", mockCtx);

    expect(result?.verdict).toBe("other");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("medium");
    expect(result?.evidence).toContain("key_elsewhere");
  });

  test("returns unknown on 401", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));

    const result = await falAdapter.ownedBy?.("key_self:sk_live_self", mockCtx);

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
    expect(result?.evidence).toBe("fal ownership list failed: admin authentication failed");
  });

  test("returns unknown on network error", async () => {
    mockFetch(() => {
      throw new Error("socket closed");
    });

    const result = await falAdapter.ownedBy?.("key_self:sk_live_self", mockCtx);

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
    expect(result?.evidence).toBe("fal ownership list failed: network error");
  });

  test("uses preloaded ownership data without a fetch", async () => {
    const result = await falAdapter.ownedBy?.("key_self:sk_live_self", mockCtx, {
      preload: {
        provider: "fal-ai",
        strategy: "list-match",
        complete: true,
        keysById: {
          key_self: { keyId: "key_self", alias: "Production", scope: "API" },
        },
      },
    });

    expect(result?.verdict).toBe("self");
    expect(calls).toHaveLength(0);
  });
});

describe("adapter-fal.preloadOwnership", () => {
  test("builds a paginated key_id index", async () => {
    mockFetch((url) => {
      if (url.includes("cursor=page_2")) {
        return new Response(
          JSON.stringify({
            keys: [{ key_id: "key_two", alias: "Staging", scope: "API" }],
            has_more: false,
          }),
          { status: 200 },
        );
      }

      return new Response(
        JSON.stringify({
          keys: [{ key_id: "key_one", alias: "Production", scope: "API" }],
          has_more: true,
          next_cursor: "page_2",
        }),
        { status: 200 },
      );
    });

    const preload = await falAdapter.preloadOwnership?.(mockCtx);

    expect(preload).toEqual({
      provider: "fal-ai",
      strategy: "list-match",
      complete: true,
      keysById: {
        key_one: { keyId: "key_one", alias: "Production", scope: "API" },
        key_two: { keyId: "key_two", alias: "Staging", scope: "API" },
      },
      evidence: "fal ownership index contains 2 key_id values",
    });
    expect(calls).toHaveLength(2);
    expect(calls[1]?.url).toContain("cursor=page_2");
  });
});
