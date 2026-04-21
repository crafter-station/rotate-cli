import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { tursoAdapter } from "../src/index.ts";

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
  varName: "TURSO_PLATFORM_TOKEN",
  token: "turso-platform-token",
};

describe("adapter-turso.create", () => {
  test("rotates existing tokens, mints a new token, and returns Secret", async () => {
    mockFetch((url) => {
      if (url.endsWith("/auth/rotate")) return new Response(null, { status: 200 });
      return new Response(JSON.stringify({ jwt: "eyJ.new.token" }), { status: 200 });
    });
    const result = await tursoAdapter.create(
      {
        secretId: "turso-main",
        adapter: "turso",
        metadata: { organization: "acme", database: "main" },
      },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.id).toBe("turso-main");
    expect(result.data?.value).toBe("eyJ.new.token");
    expect(result.data?.metadata.organization).toBe("acme");
    expect(result.data?.metadata.database).toBe("main");
    expect(result.data?.metadata.expiration).toBe("never");
    expect(result.data?.metadata.authorization).toBe("full-access");
    expect(calls[0]?.url).toContain("/v1/organizations/acme/databases/main/auth/rotate");
    expect(calls[0]?.init?.method).toBe("POST");
    expect(calls[1]?.url).toContain("/v1/organizations/acme/databases/main/auth/tokens");
    expect(calls[1]?.url).toContain("expiration=never");
    expect(calls[1]?.url).toContain("authorization=full-access");
    expect(calls[1]?.init?.method).toBe("POST");
  });

  test("missing metadata returns invalid_spec", async () => {
    const result = await tursoAdapter.create(
      { secretId: "main", adapter: "turso", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_spec");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await tursoAdapter.create(
      {
        secretId: "main",
        adapter: "turso",
        metadata: { organization: "acme", database: "main" },
      },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-turso.verify", () => {
  test("calls libSQL HTTP pipeline with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ baton: null, results: [] }), { status: 200 }));
    const secret: Secret = {
      id: "turso-main",
      provider: "turso",
      value: "eyJ.new.token",
      metadata: { organization: "acme", database: "main" },
      createdAt: new Date().toISOString(),
    };
    const r = await tursoAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toBe("https://main-acme.turso.io/v2/pipeline");
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer eyJ.new.token",
    );
  });
});

describe("adapter-turso.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "turso-main",
      provider: "turso",
      value: "eyJ.old.token",
      metadata: { organization: "acme", database: "main" },
      createdAt: new Date().toISOString(),
    };
    const r = await tursoAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls.length).toBe(0);
  });
});
