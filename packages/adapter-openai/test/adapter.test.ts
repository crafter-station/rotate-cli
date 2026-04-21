import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getAuthDefinition } from "@rotate/core/auth";
import { registerAdapter, resetRegistry } from "@rotate/core/registry";
import type { AuthContext, Secret } from "@rotate/core/types";
import { openaiAdapter } from "../src/index.ts";

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
  registerAdapter(openaiAdapter);
  delete process.env.OPENAI_ADMIN_KEY;
});

afterEach(() => {
  global.fetch = originalFetch;
  resetRegistry();
  delete process.env.OPENAI_ADMIN_KEY;
});

const mockCtx: AuthContext = {
  kind: "env",
  varName: "OPENAI_ADMIN_KEY",
  token: "sk-admin-old",
};

const mockOwnershipCtx = {
  ...mockCtx,
  knownOrgIds: new Set(["org_self"]),
  knownUserIds: new Set(["user_self"]),
};

describe("adapter-openai.create", () => {
  test("calls Admin API and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            object: "organization.admin_api_key",
            id: "key_new",
            name: "rotate-cli-main",
            redacted_value: "sk-admin...new",
            value: "sk-admin-new",
            created_at: 1711471533,
            owner: {
              type: "user",
              id: "user_123",
              name: "Jane Doe",
              role: "owner",
            },
          }),
          { status: 201 },
        ),
    );
    const result = await openaiAdapter.create(
      { secretId: "main", adapter: "openai", metadata: { name: "rotate-cli-main" } },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("sk-admin-new");
    expect(result.data?.metadata.key_id).toBe("key_new");
    expect(result.data?.metadata.redacted_value).toBe("sk-admin...new");
    expect(calls[0]?.url).toContain("/v1/organization/admin_api_keys");
    expect(calls[0]?.init?.method).toBe("POST");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await openaiAdapter.create(
      { secretId: "m", adapter: "openai", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-openai.verify", () => {
  test("calls Admin API with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ data: [] }), { status: 200 }));
    const secret: Secret = {
      id: "key_new",
      provider: "openai",
      value: "sk-admin-new",
      metadata: {},
      createdAt: new Date().toISOString(),
    };
    const r = await openaiAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/v1\/organization\/admin_api_keys\?limit=1$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer sk-admin-new",
    );
  });
});

describe("adapter-openai.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "key_old",
      provider: "openai",
      value: "sk-admin-old",
      metadata: { key_id: "key_old" },
      createdAt: new Date().toISOString(),
    };
    const r = await openaiAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
  });
});

describe("adapter-openai.auth", () => {
  test("resolves env auth through shared auth registry", async () => {
    process.env.OPENAI_ADMIN_KEY = "sk-admin-env";
    const ctx = await openaiAdapter.auth();
    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("sk-admin-env");
  });

  test("registers auth definition with the adapter", () => {
    expect(getAuthDefinition("openai")?.displayName).toBe("OpenAI");
  });
});

describe("adapter-openai.ownedBy", () => {
  test("returns self when /v1/me matches a known user", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            object: "user",
            id: "user_self",
            orgs: { data: [{ id: "org_elsewhere", title: "Elsewhere" }] },
          }),
          { status: 200 },
        ),
    );

    const result = await openaiAdapter.ownedBy?.("sk-proj-candidate", mockOwnershipCtx);

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.scope).toBe("user");
    expect(result?.confidence).toBe("high");
    expect(result?.strategy).toBe("api-introspection");
    expect(calls[0]?.url).toBe("https://api.openai.com/v1/me");
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer sk-proj-candidate",
    );
  });

  test("returns self when /v1/me matches a known org", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            object: "user",
            id: "user_collaborator",
            orgs: { data: [{ id: "org_self", title: "Self Org" }] },
          }),
          { status: 200 },
        ),
    );

    const result = await openaiAdapter.ownedBy?.("sk-candidate", mockOwnershipCtx);

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.scope).toBe("org");
    expect(result?.confidence).toBe("high");
  });

  test("returns other when /v1/me only reports external orgs", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            object: "user",
            id: "user_other",
            orgs: { data: [{ id: "org_other", title: "Other Org" }] },
          }),
          { status: 200 },
        ),
    );

    const result = await openaiAdapter.ownedBy?.("sk-candidate", mockOwnershipCtx);

    expect(result?.verdict).toBe("other");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.scope).toBe("org");
    expect(result?.confidence).toBe("high");
  });

  test("returns unknown on 401", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));

    const result = await openaiAdapter.ownedBy?.("sk-revoked", mockOwnershipCtx);

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
  });

  test("returns unknown on network error", async () => {
    global.fetch = ((url: RequestInfo | URL, init?: RequestInit) => {
      const u = typeof url === "string" ? url : url.toString();
      calls.push({ url: u, init });
      return Promise.reject(new Error("socket closed"));
    }) as FetchFn;

    const result = await openaiAdapter.ownedBy?.("sk-candidate", mockOwnershipCtx);

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.evidence).toContain("network error");
  });
});
