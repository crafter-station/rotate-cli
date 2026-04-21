import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { anthropicAdapter } from "../src/index.ts";

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
  varName: "ANTHROPIC_ADMIN_KEY",
  token: "sk-ant-admin-test",
};

describe("adapter-anthropic.create", () => {
  test("calls Admin API and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            id: "key_new",
            name: "rotate-cli-main",
            api_key: "sk-ant-admin-new",
            partial_key: "sk-ant...new",
            workspace_id: "wrk_x",
            created_at: "2026-04-20T12:00:00.000Z",
          }),
          { status: 201 },
        ),
    );
    const result = await anthropicAdapter.create(
      {
        secretId: "main",
        adapter: "anthropic",
        metadata: { name: "rotate-cli-main", workspace_id: "wrk_x" },
      },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("sk-ant-admin-new");
    expect(result.data?.metadata.key_id).toBe("key_new");
    expect(result.data?.createdAt).toBe("2026-04-20T12:00:00.000Z");
    expect(calls[0]?.url).toContain("/v1/organizations/api_keys");
    expect((calls[0]?.init?.headers as Record<string, string>)?.["x-api-key"]).toBe(
      "sk-ant-admin-test",
    );
    expect((calls[0]?.init?.headers as Record<string, string>)?.["anthropic-version"]).toBe(
      "2023-06-01",
    );
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await anthropicAdapter.create(
      { secretId: "m", adapter: "anthropic", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-anthropic.verify", () => {
  test("calls Admin API with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ data: [] }), { status: 200 }));
    const secret: Secret = {
      id: "key_new",
      provider: "anthropic",
      value: "sk-ant-admin-new",
      metadata: {},
      createdAt: new Date().toISOString(),
    };
    const r = await anthropicAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toContain("/v1/organizations/api_keys?limit=1");
    expect((calls[0]?.init?.headers as Record<string, string>)?.["x-api-key"]).toBe(
      "sk-ant-admin-new",
    );
  });
});

describe("adapter-anthropic.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "key_old",
      provider: "anthropic",
      value: "sk-ant-admin-old",
      metadata: { key_id: "key_old" },
      createdAt: new Date().toISOString(),
    };
    const r = await anthropicAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
  });
});
