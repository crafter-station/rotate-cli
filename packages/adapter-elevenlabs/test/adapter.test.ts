import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getAuthDefinition } from "@rotate/core";
import { registerAdapter, resetRegistry } from "@rotate/core/registry";
import type { AuthContext, Secret } from "@rotate/core/types";
import { elevenlabsAdapter } from "../src/index.ts";

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
  registerAdapter(elevenlabsAdapter);
  delete process.env.ELEVENLABS_ADMIN_KEY;
});

afterEach(() => {
  global.fetch = originalFetch;
  resetRegistry();
  delete process.env.ELEVENLABS_ADMIN_KEY;
});

const mockCtx: AuthContext = {
  kind: "env",
  varName: "ELEVENLABS_ADMIN_KEY",
  token: "admin_test",
};

describe("adapter-elevenlabs.create", () => {
  test("calls ElevenLabs API and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            "xi-api-key": "xi_new_secret",
            key_id: "key_new",
          }),
          { status: 200 },
        ),
    );
    const result = await elevenlabsAdapter.create(
      {
        secretId: "main",
        adapter: "elevenlabs",
        metadata: { service_account_user_id: "sa_x", character_limit: "1000000" },
      },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("xi_new_secret");
    expect(result.data?.metadata.key_id).toBe("key_new");
    expect(result.data?.metadata.service_account_user_id).toBe("sa_x");
    expect(calls[0]?.url).toContain("/v1/service-accounts/sa_x/api-keys");
  });

  test("missing service_account_user_id returns invalid_spec", async () => {
    const result = await elevenlabsAdapter.create(
      { secretId: "main", adapter: "elevenlabs", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_spec");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await elevenlabsAdapter.create(
      { secretId: "m", adapter: "elevenlabs", metadata: { service_account_user_id: "sa_x" } },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-elevenlabs.verify", () => {
  test("calls /v1/user with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ user_id: "user_x" }), { status: 200 }));
    const secret: Secret = {
      id: "key_new",
      provider: "elevenlabs",
      value: "xi_new_secret",
      metadata: {},
      createdAt: new Date().toISOString(),
    };
    const r = await elevenlabsAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/v1\/user$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.["xi-api-key"]).toBe(
      "xi_new_secret",
    );
  });
});

describe("adapter-elevenlabs.auth", () => {
  test("resolves env auth through shared auth registry", async () => {
    process.env.ELEVENLABS_ADMIN_KEY = "test-token";
    const ctx = await elevenlabsAdapter.auth();
    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("test-token");
  });

  test("registers auth definition with the adapter", () => {
    expect(getAuthDefinition("elevenlabs")?.displayName).toBe("ElevenLabs");
  });
});

describe("adapter-elevenlabs.ownedBy", () => {
  test("returns self when /v1/user user_id is pre-seeded", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            user_id: "user_self",
            seat_type: "workspace_admin",
            subscription: { tier: "Creator", status: "active" },
          }),
          { status: 200 },
        ),
    );
    const result = await elevenlabsAdapter.ownedBy?.(" xi_candidate ", {
      ...mockCtx,
      knownUserIds: new Set(["user_self"]),
      knownTiers: new Set(["Creator"]),
    } as AuthContext);
    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.confidence).toBe("medium");
    expect(result?.strategy).toBe("api-introspection");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://api.elevenlabs.io/v1/user");
    expect((calls[0]?.init?.headers as Record<string, string>)?.["xi-api-key"]).toBe(
      "xi_candidate",
    );
  });

  test("returns other when /v1/user user_id is not pre-seeded", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            user_id: "user_elsewhere",
            seat_type: null,
            subscription: { tier: "Free", status: "active" },
          }),
          { status: 200 },
        ),
    );
    const result = await elevenlabsAdapter.ownedBy?.("xi_candidate", {
      ...mockCtx,
      knownUserIds: ["user_self"],
    } as AuthContext);
    expect(result?.verdict).toBe("other");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("medium");
  });

  test("returns unknown on 401", async () => {
    mockFetch(() => new Response(JSON.stringify({ detail: "invalid_api_key" }), { status: 401 }));
    const result = await elevenlabsAdapter.ownedBy?.("xi_revoked", {
      ...mockCtx,
      knownUserIds: ["user_self"],
    } as AuthContext);
    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
  });

  test("returns unknown on network error", async () => {
    global.fetch = ((url: RequestInfo | URL, init?: RequestInit) => {
      const u = typeof url === "string" ? url : url.toString();
      calls.push({ url: u, init });
      throw new Error("connection failed");
    }) as FetchFn;
    const result = await elevenlabsAdapter.ownedBy?.("xi_candidate", {
      ...mockCtx,
      knownUserIds: ["user_self"],
    } as AuthContext);
    expect(result?.verdict).toBe("unknown");
    expect(result?.evidence).toBe("network error during ElevenLabs /v1/user ownership check");
  });

  test("returns unknown for ambiguous tier match without user_id match", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            user_id: "new_service_account",
            seat_type: "workspace_member",
            subscription: { tier: "Creator", status: "active" },
          }),
          { status: 200 },
        ),
    );
    const result = await elevenlabsAdapter.ownedBy?.("xi_candidate", {
      ...mockCtx,
      knownUserIds: ["user_self"],
      knownTiers: ["Creator"],
    } as AuthContext);
    expect(result?.verdict).toBe("unknown");
    expect(result?.confidence).toBe("medium");
    expect(result?.scope).toBe("team");
  });
});

describe("adapter-elevenlabs.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "key_old",
      provider: "elevenlabs",
      value: "xi_old_secret",
      metadata: { service_account_user_id: "sa_x", key_id: "key_old" },
      createdAt: new Date().toISOString(),
    };
    const r = await elevenlabsAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
  });
});
