import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getAuthDefinition } from "@rotate/core";
import { registerAdapter, resetRegistry } from "@rotate/core/registry";
import type { AuthContext, Secret } from "@rotate/core/types";
import { tursoAdapter } from "../src/index.ts";

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
  varName: "TURSO_PLATFORM_TOKEN",
  token: "turso-platform-token",
};

describe("adapter-turso.create", () => {
  test("rotates existing tokens, mints a new token, and returns Secret", async () => {
    mockFetch((url) => {
      if (url.endsWith("/auth/rotate")) return new Response(null, { status: 200 });
      return new Response(JSON.stringify({ jwt: "eyJ.new.token" }), { status: 200 });
    });
    const result = await tursoAdapter.create(
      {
        secretId: "turso-main",
        adapter: "turso",
        metadata: { organization: "acme", database: "main" },
      },
      mockCtx,
    );
    expect(result.ok).toBe(true);
    expect(result.data?.id).toBe("turso-main");
    expect(result.data?.value).toBe("eyJ.new.token");
    expect(result.data?.metadata.organization).toBe("acme");
    expect(result.data?.metadata.database).toBe("main");
    expect(result.data?.metadata.expiration).toBe("never");
    expect(result.data?.metadata.authorization).toBe("full-access");
    expect(calls[0]?.url).toContain("/v1/organizations/acme/databases/main/auth/rotate");
    expect(calls[0]?.init?.method).toBe("POST");
    expect(calls[1]?.url).toContain("/v1/organizations/acme/databases/main/auth/tokens");
    expect(calls[1]?.url).toContain("expiration=never");
    expect(calls[1]?.url).toContain("authorization=full-access");
    expect(calls[1]?.init?.method).toBe("POST");
  });

  test("missing metadata returns invalid_spec", async () => {
    const result = await tursoAdapter.create(
      { secretId: "main", adapter: "turso", metadata: {} },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("invalid_spec");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const result = await tursoAdapter.create(
      {
        secretId: "main",
        adapter: "turso",
        metadata: { organization: "acme", database: "main" },
      },
      mockCtx,
    );
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-turso.verify", () => {
  test("calls libSQL HTTP pipeline with new secret", async () => {
    mockFetch(() => new Response(JSON.stringify({ baton: null, results: [] }), { status: 200 }));
    const secret: Secret = {
      id: "turso-main",
      provider: "turso",
      value: "eyJ.new.token",
      metadata: { organization: "acme", database: "main" },
      createdAt: new Date().toISOString(),
    };
    const r = await tursoAdapter.verify(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls[0]?.url).toBe("https://main-acme.turso.io/v2/pipeline");
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer eyJ.new.token",
    );
  });
});

describe("adapter-turso.revoke", () => {
  test("is idempotent on 404", async () => {
    mockFetch(() => new Response("not found", { status: 404 }));
    const secret: Secret = {
      id: "turso-main",
      provider: "turso",
      value: "eyJ.old.token",
      metadata: { organization: "acme", database: "main" },
      createdAt: new Date().toISOString(),
    };
    const r = await tursoAdapter.revoke(secret, mockCtx);
    expect(r.ok).toBe(true);
    expect(calls.length).toBe(0);
  });
});

describe("adapter-turso.auth", () => {
  beforeEach(() => {
    resetRegistry();
    registerAdapter(tursoAdapter);
    delete process.env.TURSO_PLATFORM_TOKEN;
  });

  afterEach(() => {
    resetRegistry();
    delete process.env.TURSO_PLATFORM_TOKEN;
  });

  test("resolves env auth through shared auth registry", async () => {
    process.env.TURSO_PLATFORM_TOKEN = "test-token";
    const ctx = await tursoAdapter.auth();
    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("test-token");
  });

  test("registers auth definition with the adapter", () => {
    expect(getAuthDefinition("turso")?.displayName).toBe("Turso");
  });
});

describe("adapter-turso.ownedBy", () => {
  test("returns self when a co-located Turso URL uses an admin organization", async () => {
    mockFetch(() =>
      Response.json({
        organizations: [{ slug: "acme" }],
      }),
    );

    const result = await tursoAdapter.ownedBy?.("eyJ.db.token", mockCtx, {
      coLocatedVars: {
        TURSO_DATABASE_URL: "libsql://main-acme.turso.io",
      },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.confidence).toBe("high");
    expect(result?.strategy).toBe("format-decode");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://api.turso.tech/v1/organizations");
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer turso-platform-token",
    );
  });

  test("returns other when the Turso URL organization is not visible to the admin token", async () => {
    mockFetch(() =>
      Response.json({
        organizations: [{ slug: "acme" }],
      }),
    );

    const result = await tursoAdapter.ownedBy?.("libsql://main-elsewhere.turso.io", mockCtx);

    expect(result?.verdict).toBe("other");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("high");
    expect(result?.strategy).toBe("format-decode");
  });

  test("returns unknown when organization lookup is unauthorized", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));

    const result = await tursoAdapter.ownedBy?.("libsql://main-acme.turso.io", mockCtx);

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
    expect(result?.evidence).toBe("admin Turso organization lookup failed");
  });

  test("returns unknown when organization lookup hits a network error", async () => {
    mockFetch(() => {
      throw new Error("socket closed");
    });

    const result = await tursoAdapter.ownedBy?.("libsql://main-acme.turso.io", mockCtx);

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
    expect(result?.evidence).toBe("admin Turso organization lookup unavailable");
  });

  test("returns unknown for an orphan Turso-shaped JWT", async () => {
    const payload = btoa(JSON.stringify({ exp: 4_102_444_800, iat: 1, p: {} }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");

    const result = await tursoAdapter.ownedBy?.(`eyJ.${payload}.sig`, mockCtx);

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
    expect(calls).toHaveLength(0);
  });
});

describe("adapter-turso.preloadOwnership", () => {
  test("builds an organization and database hostname index", async () => {
    mockFetch((url) => {
      if (url.endsWith("/v1/organizations")) {
        return Response.json({
          organizations: [{ slug: "acme" }, { name: "team-b" }],
        });
      }
      if (url.endsWith("/v1/organizations/acme/databases")) {
        return Response.json({
          databases: [{ Name: "main", Hostname: "main-acme.turso.io" }],
        });
      }
      return Response.json({
        databases: [{ name: "analytics", hostname: "analytics-team-b.turso.io" }],
      });
    });

    const preload = await tursoAdapter.preloadOwnership?.(mockCtx);

    expect(preload?.selfOrgSlugs).toEqual(["acme", "team-b"]);
    expect(preload?.dbIndex).toEqual([
      { org: "acme", db: "main", hostname: "main-acme.turso.io" },
      { org: "team-b", db: "analytics", hostname: "analytics-team-b.turso.io" },
    ]);
    expect(calls.map((call) => call.url)).toEqual([
      "https://api.turso.tech/v1/organizations",
      "https://api.turso.tech/v1/organizations/acme/databases",
      "https://api.turso.tech/v1/organizations/team-b/databases",
    ]);
  });
});
