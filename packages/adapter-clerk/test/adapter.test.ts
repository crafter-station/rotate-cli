import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getAuthDefinition } from "@rotate/core/auth";
import { registerAdapter, resetRegistry } from "@rotate/core/registry";
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
  resetRegistry();
  registerAdapter(clerkAdapter);
  delete process.env.CLERK_PLAPI_TOKEN;
});

afterEach(() => {
  global.fetch = originalFetch;
  resetRegistry();
  delete process.env.CLERK_PLAPI_TOKEN;
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

describe("adapter-clerk.auth", () => {
  test("resolves env auth through shared auth registry", async () => {
    process.env.CLERK_PLAPI_TOKEN = "test-token";
    const ctx = await clerkAdapter.auth();
    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("test-token");
  });

  test("registers auth definition with the adapter", () => {
    expect(getAuthDefinition("clerk")?.displayName).toBe("Clerk");
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

describe("adapter-clerk.ownedBy", () => {
  test("returns self when co-located publishable key decodes to a known FAPI host", async () => {
    const pk = publishableKey("test", "example.accounts.dev");
    const result = await clerkAdapter.ownedBy?.("sk_test_candidate", mockCtx, {
      coLocatedVars: { NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY: pk },
      preload: { knownFapiHosts: ["example.accounts.dev"] },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.confidence).toBe("high");
    expect(result?.strategy).toBe("format-decode");
    expect(calls.length).toBe(0);
  });

  test("returns other when co-located publishable key decodes to an unknown FAPI host", async () => {
    const pk = publishableKey("live", "foreign.accounts.dev");
    const result = await clerkAdapter.ownedBy?.("sk_live_candidate", mockCtx, {
      coLocatedVars: { NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY: pk },
      preload: { knownFapiHosts: ["example.accounts.dev"] },
    });

    expect(result?.verdict).toBe("other");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("high");
    expect(result?.strategy).toBe("format-decode");
    expect(calls.length).toBe(0);
  });

  test("uses JWKS fallback when no publishable key is available", async () => {
    mockFetch(
      () =>
        new Response(JSON.stringify({ keys: [{ kid: "ins_known_abc" }] }), {
          status: 200,
        }),
    );

    const result = await clerkAdapter.ownedBy?.("sk_live_candidate", mockCtx, {
      preload: { knownKids: ["ins_known_abc"] },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.strategy).toBe("api-introspection");
    expect(calls[0]?.url).toMatch(/\/v1\/jwks$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer sk_live_candidate",
    );
  });

  test("returns unknown on JWKS 401", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));

    const result = await clerkAdapter.ownedBy?.("sk_live_candidate", mockCtx, {
      preload: { knownKids: ["ins_known_abc"] },
    });

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.strategy).toBe("api-introspection");
  });

  test("returns unknown on JWKS network error", async () => {
    mockFetch(() => {
      throw new Error("socket closed");
    });

    const result = await clerkAdapter.ownedBy?.("sk_live_candidate", mockCtx, {
      preload: { knownKids: ["ins_known_abc"] },
    });

    expect(result?.verdict).toBe("unknown");
    expect(result?.evidence).toBe("provider unavailable");
    expect(result?.strategy).toBe("api-introspection");
  });

  test("inherits webhook secret ownership from sibling Clerk secret", async () => {
    const pk = publishableKey("test", "example.accounts.dev");
    const result = await clerkAdapter.ownedBy?.("whsec_candidate", mockCtx, {
      coLocatedVars: {
        CLERK_SECRET_KEY: "sk_test_candidate",
        NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY: pk,
      },
      preload: { knownFapiHosts: ["example.accounts.dev"] },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.confidence).toBe("medium");
    expect(result?.strategy).toBe("sibling-inheritance");
    expect(calls.length).toBe(0);
  });
});

function publishableKey(environment: "live" | "test", host: string): string {
  return `pk_${environment}_${Buffer.from(`${host}$`, "utf8").toString("base64")}`;
}
