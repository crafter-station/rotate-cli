import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { AuthContext, Secret } from "@rotate/core/types";
import { supabaseAdapter } from "../src/index.ts";

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
  varName: "SUPABASE_ACCESS_TOKEN",
  token: "sbp_test",
};

describe("adapter-supabase.create", () => {
  test("calls Management API and returns Secret", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            api_key: "sb_secret_abc",
            id: "key_new",
            type: "secret",
            prefix: "sb_secret",
            name: "rotate-cli-test",
            inserted_at: "2026-04-21T10:00:00Z",
          }),
          { status: 201 },
        ),
    );
    const result = await supabaseAdapter.create(
      { secretId: "main", adapter: "supabase", metadata: { project_ref: "abc123" } },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("sb_secret_abc");
    expect(result.data?.metadata.key_id).toBe("key_new");
    expect(result.data?.metadata.project_ref).toBe("abc123");
    expect(calls[0]?.url).toContain("/v1/projects/abc123/api-keys?reveal=true");
  });

  test("missing project_ref returns invalid_spec", async () => {
    const result = await supabaseAdapter.create(
      { secretId: "main", adapter: "supabase", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_spec");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await supabaseAdapter.create(
      { secretId: "m", adapter: "supabase", metadata: { project_ref: "abc123" } },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-supabase.verify", () => {
  test("calls project REST API with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ swagger: "2.0" }), { status: 200 }));
    const secret: Secret = {
      id: "key_new",
      provider: "supabase",
      value: "sb_secret_abc",
      metadata: { project_ref: "abc123" },
      createdAt: new Date().toISOString(),
    };
    const r = await supabaseAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toBe("https://abc123.supabase.co/rest/v1/");
    expect((calls[0]?.init?.headers as Record<string, string>)?.apikey).toBe("sb_secret_abc");
  });
});

describe("adapter-supabase.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "key_old",
      provider: "supabase",
      value: "sb_secret_old",
      metadata: { project_ref: "abc123", key_id: "key_old" },
      createdAt: new Date().toISOString(),
    };
    const r = await supabaseAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
  });
});

describe("adapter-supabase.ownedBy", () => {
  test("returns self for co-located Supabase URL", async () => {
    mockFetch(() =>
      Response.json([{ id: "abcdefghijklmnopqrst" }, { id: "uvwxyzabcdef12345678" }]),
    );

    const result = await supabaseAdapter.ownedBy?.("sb_secret_unused", mockCtx, {
      coLocatedVars: {
        SUPABASE_URL: "https://abcdefghijklmnopqrst.supabase.co",
      },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.confidence).toBe("high");
    expect(result?.strategy).toBe("sibling-inheritance");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://api.supabase.com/v1/projects");
  });

  test("returns other for legacy JWT from a different project", async () => {
    mockFetch(() => Response.json([{ id: "abcdefghijklmnopqrst" }]));

    const result = await supabaseAdapter.ownedBy?.(
      jwt({ iss: "supabase", ref: "uvwxyzabcdef12345678", role: "service_role" }),
      mockCtx,
    );

    expect(result?.verdict).toBe("other");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("high");
    expect(result?.strategy).toBe("format-decode");
  });

  test("returns self for opaque key matched by API introspection", async () => {
    mockFetch((url) => {
      if (url.endsWith("/v1/projects")) {
        return Response.json([{ id: "abcdefghijklmnopqrst" }]);
      }
      if (url.endsWith("/v1/projects/abcdefghijklmnopqrst/api-keys?reveal=true")) {
        return Response.json([
          {
            id: "secret-key",
            api_key: "sb_secret_match",
          },
        ]);
      }
      return new Response("not found", { status: 404 });
    });

    const result = await supabaseAdapter.ownedBy?.("sb_secret_match", mockCtx);

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.confidence).toBe("medium");
    expect(result?.strategy).toBe("api-introspection");
    expect(calls).toHaveLength(2);
  });

  test("returns unknown on 401", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));

    const result = await supabaseAdapter.ownedBy?.(
      jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon" }),
      mockCtx,
    );

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
    expect(result?.strategy).toBe("format-decode");
  });

  test("returns unknown on network error", async () => {
    mockFetch(() => {
      throw new Error("offline");
    });

    const result = await supabaseAdapter.ownedBy?.(
      jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon" }),
      mockCtx,
    );

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
    expect(result?.strategy).toBe("format-decode");
  });
});

function jwt(payload: Record<string, unknown>): string {
  return `${base64Url({ alg: "HS256", typ: "JWT" })}.${base64Url(payload)}.signature`;
}

function base64Url(value: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(value), "utf8")
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}
