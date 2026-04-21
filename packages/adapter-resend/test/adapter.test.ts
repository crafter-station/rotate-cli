import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { resendAdapter } from "../src/index.ts";

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

const mockCtx: AuthContext = { kind: "env", varName: "RESEND_API_KEY", token: "re_old" };

describe("adapter-resend.create", () => {
  test("calls Resend API and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            id: "key_new",
            token: "re_new",
          }),
          { status: 201 },
        ),
    );
    const result = await resendAdapter.create(
      {
        secretId: "main",
        adapter: "resend",
        metadata: { name: "Production", permission: "full_access" },
      },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("re_new");
    expect(result.data?.metadata.key_id).toBe("key_new");
    expect(result.data?.metadata.name).toBe("Production");
    expect(calls[0]?.url).toContain("/api-keys");
    expect(calls[0]?.init?.method).toBe("POST");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await resendAdapter.create(
      { secretId: "m", adapter: "resend", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-resend.verify", () => {
  test("calls /api-keys with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ data: [] }), { status: 200 }));
    const secret: Secret = {
      id: "key_new",
      provider: "resend",
      value: "re_new",
      metadata: {},
      createdAt: new Date().toISOString(),
    };
    const r = await resendAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/api-keys$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer re_new",
    );
  });
});

describe("adapter-resend.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "key_old",
      provider: "resend",
      value: "re_old",
      metadata: { key_id: "key_old" },
      createdAt: new Date().toISOString(),
    };
    const r = await resendAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
  });
});
