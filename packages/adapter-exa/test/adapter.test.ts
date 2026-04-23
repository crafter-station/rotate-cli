import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getAuthDefinition } from "@rotate/core/auth";
import { registerAdapter, resetRegistry } from "@rotate/core/registry";
import type { AuthContext, Secret } from "@rotate/core/types";
import { adapterExaAdapter } from "../src/index.ts";

type FetchFn = typeof fetch;

const originalFetch = global.fetch;
let calls: Array<{ url: string; init?: RequestInit }> = [];

function mockFetch(responder: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  global.fetch = ((url: Parameters<FetchFn>[0], init?: Parameters<FetchFn>[1]) => {
    const u = typeof url === "string" ? url : url.toString();
    calls.push({ url: u, init });
    return Promise.resolve(responder(u, init));
  }) as FetchFn;
}

beforeEach(() => {
  calls = [];
  resetRegistry();
  registerAdapter(adapterExaAdapter);
  delete process.env.EXA_API_KEY;
});

afterEach(() => {
  global.fetch = originalFetch;
  resetRegistry();
  delete process.env.EXA_API_KEY;
});

const mockCtx: AuthContext = { kind: "env", varName: "EXA_API_KEY", token: "exa_old" };

function mockIO(pasted: string, confirm = true): import("@rotate/core/types").PromptIO {
  return {
    isInteractive: true,
    async promptSecret() {
      return pasted;
    },
    async confirm() {
      return confirm;
    },
    async select<T>() {
      return undefined as unknown as T;
    },
    note(_: string) {},
    async close() {},
  } as unknown as import("@rotate/core/types").PromptIO;
}

describe("adapter-exa.create (manual-assist)", () => {
  test("prompts for new key and returns it", async () => {
    const io = mockIO("exa_NEWPASTE");
    const result = await adapterExaAdapter.create(
      { secretId: "main", adapter: "exa", metadata: {}, io },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("exa_NEWPASTE");
    expect(result.data?.metadata.manual_assist).toBe("true");
  });

  test("without interactive IO returns unsupported", async () => {
    const result = await adapterExaAdapter.create(
      { secretId: "main", adapter: "exa", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("unsupported");
  });
});

describe("adapter-exa.verify", () => {
  test("calls list API keys with the new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ apiKeys: [] }), { status: 200 }));
    const secret: Secret = {
      id: "key_new",
      provider: "exa",
      value: "exa_new",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterExaAdapter.verify(secret, mockCtx);

    expect(result.ok).toBe(true);
    expect(calls[0]?.url).toBe("https://admin-api.exa.ai/team-management/api-keys");
    expect((calls[0]?.init?.headers as Record<string, string>)?.["x-api-key"]).toBe("exa_new");
  });
});

describe("adapter-exa.revoke", () => {
  test("deletes the stored key id", async () => {
    mockFetch(() => new Response(JSON.stringify({ success: true }), { status: 200 }));
    const secret: Secret = {
      id: "key_old",
      provider: "exa",
      value: "exa_old",
      metadata: { key_id: "key_old" },
      createdAt: new Date().toISOString(),
    };

    const result = await adapterExaAdapter.revoke(secret, mockCtx);

    expect(result.ok).toBe(true);
    expect(calls[0]?.url).toBe("https://admin-api.exa.ai/team-management/api-keys/key_old");
    expect(calls[0]?.init?.method).toBe("DELETE");
  });

  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "key_old",
      provider: "exa",
      value: "exa_old",
      metadata: { key_id: "key_old" },
      createdAt: new Date().toISOString(),
    };

    const result = await adapterExaAdapter.revoke(secret, mockCtx);

    expect(result.ok).toBe(true);
  });
});

describe("adapter-exa.auth", () => {
  test("resolves env auth through shared auth registry", async () => {
    process.env.EXA_API_KEY = "exa_env";
    const ctx = await adapterExaAdapter.auth();
    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("exa_env");
  });

  test("registers auth definition with the adapter", () => {
    expect(getAuthDefinition("exa")?.displayName).toBe("Exa");
    expect(getAuthDefinition("exa")?.envVars).toEqual(["EXA_API_KEY"]);
  });
});

describe("adapter-exa.ownedBy", () => {
  test("returns self when candidate team id matches preload", async () => {
    mockFetch(() =>
      Response.json({
        apiKeys: [
          {
            id: "key_new",
            name: "Production",
            teamId: "team_1",
          },
        ],
      }),
    );

    const result = await adapterExaAdapter.ownedBy?.("exa_candidate", mockCtx, {
      preload: {
        provider: "exa",
        strategy: "api-introspection",
        team: { id: "team_1" },
        apiKeys: [{ id: "key_old" }],
      },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.confidence).toBe("high");
    expect(result?.strategy).toBe("api-introspection");
    expect((calls[0]?.init?.headers as Record<string, string>)?.["x-api-key"]).toBe(
      "exa_candidate",
    );
  });

  test("returns other when candidate team id differs from preload", async () => {
    mockFetch(() =>
      Response.json({
        apiKeys: [
          {
            id: "key_new",
            teamId: "team_2",
          },
        ],
      }),
    );

    const result = await adapterExaAdapter.ownedBy?.("exa_candidate", mockCtx, {
      preload: {
        provider: "exa",
        strategy: "api-introspection",
        team: { id: "team_1" },
        apiKeys: [{ id: "key_old" }],
      },
    });

    expect(result?.verdict).toBe("other");
    expect(result?.adminCanBill).toBe(false);
  });

  test("returns unknown on 403", async () => {
    mockFetch(() => new Response("forbidden", { status: 403 }));

    const result = await adapterExaAdapter.ownedBy?.("exa_candidate", mockCtx, {
      preload: {
        provider: "exa",
        strategy: "api-introspection",
        team: { id: "team_1" },
        apiKeys: [{ id: "key_old" }],
      },
    });

    expect(result?.verdict).toBe("unknown");
    expect(result?.strategy).toBe("api-introspection");
  });
});

describe("adapter-exa.preloadOwnership", () => {
  test("builds the expected team and key inventory", async () => {
    mockFetch(() =>
      Response.json({
        apiKeys: [
          {
            id: "key_1",
            name: "Production",
            teamId: "team_1",
            createdAt: "2026-01-01T00:00:00.000Z",
          },
        ],
      }),
    );

    const result = await adapterExaAdapter.preloadOwnership?.(mockCtx);

    expect(result).toEqual({
      provider: "exa",
      strategy: "api-introspection",
      team: { id: "team_1" },
      apiKeys: [
        {
          id: "key_1",
          name: "Production",
          createdAt: "2026-01-01T00:00:00.000Z",
        },
      ],
    });
  });
});
