import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getAuthDefinition } from "@rotate/core/auth";
import { registerAdapter, resetRegistry } from "@rotate/core/registry";
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
  resetRegistry();
  registerAdapter(anthropicAdapter);
  delete process.env.ANTHROPIC_ADMIN_KEY;
});

afterEach(() => {
  global.fetch = originalFetch;
  resetRegistry();
  delete process.env.ANTHROPIC_ADMIN_KEY;
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

describe("adapter-anthropic.auth", () => {
  test("resolves env auth through shared auth registry", async () => {
    process.env.ANTHROPIC_ADMIN_KEY = "sk-ant-admin-env";
    const ctx = await anthropicAdapter.auth();
    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("sk-ant-admin-env");
  });

  test("registers auth definition with the adapter", () => {
    expect(getAuthDefinition("anthropic")?.displayName).toBe("Anthropic");
  });
});

describe("adapter-anthropic.ownedBy", () => {
  const suspectKey = "sk-ant-api03-owned";

  test("returns self when the admin list matches the env var name", async () => {
    mockFetch((url) => {
      if (url.endsWith("/v1/organizations/me")) {
        return new Response(JSON.stringify({ id: "org_123", name: "Crafter Station" }), {
          status: 200,
        });
      }
      return new Response(
        JSON.stringify({
          data: [
            {
              id: "apikey_123",
              name: "ANTHROPIC_API_KEY",
              status: "active",
              workspace_id: "wrk_123",
              created_at: "2026-04-21T10:00:00.000Z",
            },
          ],
          has_more: false,
        }),
        { status: 200 },
      );
    });

    const result = await anthropicAdapter.ownedBy?.(suspectKey, mockCtx, {
      coLocatedVars: { ANTHROPIC_API_KEY: suspectKey },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.confidence).toBe("medium");
    expect(result?.strategy).toBe("list-match");
    expect(calls).toHaveLength(2);
    expect(calls.some((call) => call.init?.method === "POST")).toBe(false);
  });

  test("returns other when the authenticated admin list has no match", async () => {
    mockFetch((url) => {
      if (url.endsWith("/v1/organizations/me")) {
        return new Response(JSON.stringify({ id: "org_123", name: "Crafter Station" }), {
          status: 200,
        });
      }
      return new Response(
        JSON.stringify({
          data: [
            {
              id: "apikey_elsewhere",
              name: "production",
              status: "active",
              workspace_id: "wrk_123",
              created_at: "2026-04-21T10:00:00.000Z",
            },
          ],
          has_more: false,
        }),
        { status: 200 },
      );
    });

    const result = await anthropicAdapter.ownedBy?.(suspectKey, mockCtx, {
      coLocatedVars: { ANTHROPIC_API_KEY: suspectKey },
    });

    expect(result?.verdict).toBe("other");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
    expect(result?.strategy).toBe("list-match");
  });

  test("returns unknown on 401", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));

    const result = await anthropicAdapter.ownedBy?.(suspectKey, mockCtx, {
      coLocatedVars: { ANTHROPIC_API_KEY: suspectKey },
    });

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.strategy).toBe("list-match");
    expect(result?.evidence).toContain("401");
  });

  test("returns unknown on network error", async () => {
    mockFetch(() => {
      throw new Error("socket closed");
    });

    const result = await anthropicAdapter.ownedBy?.(suspectKey, mockCtx, {
      coLocatedVars: { ANTHROPIC_API_KEY: suspectKey },
    });

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.strategy).toBe("list-match");
    expect(result?.evidence).toContain("socket closed");
  });

  test("returns self from sibling inheritance", async () => {
    const result = await anthropicAdapter.ownedBy?.(suspectKey, mockCtx, {
      preload: { keys: [], siblingOwnership: "self" },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
    expect(result?.strategy).toBe("sibling-inheritance");
    expect(calls).toHaveLength(0);
  });
});

describe("adapter-anthropic.preloadOwnership", () => {
  test("builds an org and active key index", async () => {
    mockFetch((url) => {
      if (url.endsWith("/v1/organizations/me")) {
        return new Response(JSON.stringify({ id: "org_123", name: "Crafter Station" }), {
          status: 200,
        });
      }
      return new Response(
        JSON.stringify({
          data: [
            {
              id: "apikey_123",
              name: "ANTHROPIC_API_KEY",
              status: "active",
              workspace_id: "wrk_123",
              created_at: "2026-04-21T10:00:00.000Z",
            },
          ],
          has_more: false,
        }),
        { status: 200 },
      );
    });

    const preload = await anthropicAdapter.preloadOwnership?.(mockCtx);

    expect(preload).toEqual({
      org: { id: "org_123", name: "Crafter Station" },
      keys: [
        {
          id: "apikey_123",
          name: "ANTHROPIC_API_KEY",
          workspaceId: "wrk_123",
          createdAt: "2026-04-21T10:00:00.000Z",
          partialKey: undefined,
          status: "active",
        },
      ],
    });
    expect(calls[0]?.url).toContain("/v1/organizations/me");
    expect(calls[1]?.url).toContain("/v1/organizations/api_keys?limit=1000&status=active");
  });
});
