import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { upstashAdapter } from "../src/index.ts";

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

const mockCtx: AuthContext = {
  kind: "env",
  varName: "UPSTASH_EMAIL,UPSTASH_API_KEY",
  token: "dev@example.com:mgmt_key",
};

describe("adapter-upstash.create", () => {
  test("calls reset-password and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            database_id: "db_123",
            rest_token: "rest_new",
            password: "password_new",
            last_password_rotation: "2026-04-21T12:00:00.000Z",
          }),
          { status: 200 },
        ),
    );
    const result = await upstashAdapter.create(
      { secretId: "main", adapter: "upstash", metadata: { database_id: "db_123" } },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.id).toBe("db_123");
    expect(result.data?.value).toBe("rest_new");
    expect(result.data?.metadata.database_id).toBe("db_123");
    expect(result.data?.createdAt).toBe("2026-04-21T12:00:00.000Z");
    expect(calls[0]?.url).toContain("/v2/redis/reset-password/db_123");
    expect(calls[0]?.init?.method).toBe("POST");
  });

  test("missing database_id returns invalid_spec", async () => {
    const result = await upstashAdapter.create(
      { secretId: "main", adapter: "upstash", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_spec");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await upstashAdapter.create(
      { secretId: "m", adapter: "upstash", metadata: { database_id: "db_123" } },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-upstash.verify", () => {
  test("calls database endpoint with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ database_id: "db_123" }), { status: 200 }));
    const secret: Secret = {
      id: "db_123",
      provider: "upstash",
      value: "rest_new",
      metadata: { database_id: "db_123" },
      createdAt: new Date().toISOString(),
    };
    const r = await upstashAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/v2\/redis\/database\/db_123$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      `Basic ${Buffer.from("dev@example.com:rest_new").toString("base64")}`,
    );
  });
});

describe("adapter-upstash.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "db_123",
      provider: "upstash",
      value: "rest_old",
      metadata: { database_id: "db_123" },
      createdAt: new Date().toISOString(),
    };
    const r = await upstashAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls).toHaveLength(0);
  });
});
