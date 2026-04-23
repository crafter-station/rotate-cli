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

describe("adapter-clerk.create (manual-assist)", () => {
  test("prompts for a new Secret Key and returns it as the rotation value", async () => {
    const io = mockIO("sk_live_NEWPASTE123");
    const result = await clerkAdapter.create(
      {
        secretId: "main",
        adapter: "clerk",
        metadata: {},
        io,
        currentValue: "sk_live_old",
        coLocatedVars: { CLERK_PUBLISHABLE_KEY: "pk_test_ZXhhbXBsZS5hY2NvdW50cy5kZXYk" },
        preload: {
          hostToInstance: new Map([
            [
              "example.accounts.dev",
              { instanceId: "ins_x", appId: "app_123", environment: "development" },
            ],
          ]),
        },
      },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("sk_live_NEWPASTE123");
    expect(result.data?.metadata.manual_assist).toBe("true");
    expect(result.data?.metadata.app_id).toBe("app_123");
    expect(result.data?.metadata.instance_id).toBe("ins_x");
  });

  test("rejects values that do not look like Clerk Secret Keys", async () => {
    const io = mockIO("not-a-key");
    const result = await clerkAdapter.create(
      { secretId: "main", adapter: "clerk", metadata: {}, io },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_spec");
  });

  test("without an interactive IO returns unsupported", async () => {
    const result = await clerkAdapter.create(
      { secretId: "main", adapter: "clerk", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("unsupported");
  });
});

describe("adapter-clerk.verify", () => {
  test("calls /v1/jwks with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ keys: [] }), { status: 200 }));
    const secret: Secret = {
      id: "key_new",
      provider: "clerk",
      value: "sk_live_abc",
      metadata: {},
      createdAt: new Date().toISOString(),
    };
    const r = await clerkAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/v1\/jwks$/);
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

describe("adapter-clerk.revoke (manual-assist)", () => {
  test("succeeds when user confirms dashboard deletion", async () => {
    const io = mockIO("", true);
    const secret: Secret = {
      id: "key_old",
      provider: "clerk",
      value: "sk_live_old",
      metadata: { instance_id: "ins_x", app_id: "app_123", key_id: "key_old" },
      createdAt: new Date().toISOString(),
    };
    const r = await clerkAdapter.revoke(secret, mockCtx, { io });
    expect(r.ok).toBe(true);
  });

  test("fails when user declines confirmation", async () => {
    const io = mockIO("", false);
    const secret: Secret = {
      id: "key_old",
      provider: "clerk",
      value: "sk_live_old",
      metadata: { instance_id: "ins_x" },
      createdAt: new Date().toISOString(),
    };
    const r = await clerkAdapter.revoke(secret, mockCtx, { io });
    expect(r.ok).toBe(false);
    expect(r.error?.code).toBe("unsupported");
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

  test("returns other on JWKS 401 (sk_ rejected by PLAPI → belongs elsewhere)", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));

    const result = await clerkAdapter.ownedBy?.("sk_live_candidate", mockCtx, {
      preload: { knownKids: ["ins_known_abc"] },
    });

    expect(result?.verdict).toBe("other");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("medium");
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
