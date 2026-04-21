import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getAuthDefinition } from "@rotate/core/auth";
import { registerAdapter, resetRegistry } from "@rotate/core/registry";
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
  resetRegistry();
  registerAdapter(resendAdapter);
  delete process.env.RESEND_API_KEY;
});

afterEach(() => {
  global.fetch = originalFetch;
  resetRegistry();
  delete process.env.RESEND_API_KEY;
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

describe("adapter-resend.auth", () => {
  test("resolves env auth through shared auth registry", async () => {
    process.env.RESEND_API_KEY = "re_env";
    const ctx = await resendAdapter.auth();
    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("re_env");
  });

  test("registers auth definition with the adapter", () => {
    expect(getAuthDefinition("resend")?.displayName).toBe("Resend");
    expect(getAuthDefinition("resend")?.notes?.[0]).toContain("Full access");
  });
});

describe("adapter-resend.ownedBy", () => {
  test("returns self when candidate domains match preload", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            data: [{ id: "domain_1", name: "example.com" }],
          }),
          { status: 200 },
        ),
    );

    const result = await resendAdapter.ownedBy?.("re_candidate", mockCtx, {
      preload: { knownDomainIds: ["domain_1"], knownDomainNames: ["example.com"] },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.confidence).toBe("medium");
    expect(result?.strategy).toBe("list-match");
    expect(calls[0]?.url).toMatch(/\/domains$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer re_candidate",
    );
  });

  test("returns other when candidate domains are disjoint from preload", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            data: [{ id: "domain_other", name: "elsewhere.com" }],
          }),
          { status: 200 },
        ),
    );

    const result = await resendAdapter.ownedBy?.("re_candidate", mockCtx, {
      preload: { knownDomainIds: ["domain_1"], knownDomainNames: ["example.com"] },
    });

    expect(result?.verdict).toBe("other");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.strategy).toBe("list-match");
  });

  test("returns unknown on 401", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));

    const result = await resendAdapter.ownedBy?.("re_candidate", mockCtx, {
      preload: { knownDomainIds: ["domain_1"], knownDomainNames: ["example.com"] },
    });

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.strategy).toBe("list-match");
  });

  test("returns unknown on network error", async () => {
    mockFetch(() => {
      throw new Error("boom");
    });

    const result = await resendAdapter.ownedBy?.("re_candidate", mockCtx, {
      preload: { knownDomainIds: ["domain_1"], knownDomainNames: ["example.com"] },
    });

    expect(result?.verdict).toBe("unknown");
    expect(result?.evidence).toContain("network error");
  });

  test("uses sibling inheritance for send-only keys", async () => {
    mockFetch(() => new Response("forbidden", { status: 403 }));

    const result = await resendAdapter.ownedBy?.("re_candidate", mockCtx, {
      preload: {
        knownDomainIds: ["domain_1"],
        knownDomainNames: ["example.com"],
        vercelSiblingOwnership: "self",
      },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.confidence).toBe("low");
    expect(result?.strategy).toBe("sibling-inheritance");
  });
});

describe("adapter-resend.preloadOwnership", () => {
  test("builds the expected domain fingerprint", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            data: [
              { id: "domain_1", name: "example.com" },
              { id: "domain_2", name: "mail.example.com" },
            ],
          }),
          { status: 200 },
        ),
    );

    const preload = await resendAdapter.preloadOwnership?.(mockCtx);

    expect(preload).toEqual({
      knownDomainIds: ["domain_1", "domain_2"],
      knownDomainNames: ["example.com", "mail.example.com"],
    });
    expect(calls[0]?.url).toMatch(/\/domains$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer re_old",
    );
  });
});
