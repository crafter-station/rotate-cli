import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getAuthDefinition } from "@rotate/core/auth";
import { registerAdapter, resetRegistry } from "@rotate/core/registry";
import type {
  AuthContext,
  PromptChoice,
  PromptConfirmOptions,
  PromptIO,
  Secret,
} from "@rotate/core/types";
import { adapterUploadthingAdapter } from "../src/index.ts";

type FetchFn = typeof fetch;

const originalFetch = global.fetch;
let calls: Array<{ url: string; init?: RequestInit }> = [];

function mockFetch(responder: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  global.fetch = ((url: Parameters<FetchFn>[0], init?: RequestInit) => {
    const u = typeof url === "string" ? url : url.toString();
    calls.push({ url: u, init });
    return Promise.resolve(responder(u, init));
  }) as FetchFn;
}

beforeEach(() => {
  calls = [];
  resetRegistry();
  registerAdapter(adapterUploadthingAdapter);
  delete process.env.UPLOADTHING_TOKEN;
  delete process.env.UPLOADTHING_SECRET;
  delete process.env.UPLOADTHING_APP_ID;
});

afterEach(() => {
  global.fetch = originalFetch;
  resetRegistry();
  delete process.env.UPLOADTHING_TOKEN;
  delete process.env.UPLOADTHING_SECRET;
  delete process.env.UPLOADTHING_APP_ID;
});

const mockCtx: AuthContext = { kind: "env", varName: "UPLOADTHING_TOKEN", token: "ut_old" };

function tokenWithAppId(appId: string): string {
  return Buffer.from(JSON.stringify({ appId }), "utf8").toString("base64url");
}

function mockIO(
  options: { interactive?: boolean; secret?: string; confirm?: boolean } = {},
): PromptIO {
  return {
    isInteractive: options.interactive ?? true,
    note(_message: string): void {},
    async promptLine(_message: string): Promise<string> {
      return "";
    },
    async promptSecret(_message: string): Promise<string> {
      return options.secret ?? "ut_new";
    },
    async select(_message: string, choices: PromptChoice[]): Promise<string> {
      return choices[0]?.value ?? "";
    },
    async confirm(_message: string, _confirmOptions?: PromptConfirmOptions): Promise<boolean> {
      return options.confirm ?? true;
    },
    async close(): Promise<void> {},
  };
}

describe("adapter-uploadthing.create", () => {
  test("prompts for a dashboard-created token and returns Secret", async () => {
    const result = await adapterUploadthingAdapter.create(
      {
        secretId: "main",
        adapter: "uploadthing",
        metadata: {},
        io: mockIO({ secret: tokenWithAppId("app_123") }),
      },
      mockCtx,
    );

    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe(tokenWithAppId("app_123"));
    expect(result.data?.metadata.app_id).toBe("app_123");
    expect(result.data?.metadata.rotation_mode).toBe("manual-assist");
    expect(calls).toHaveLength(0);
  });

  test("non-interactive IO returns unsupported", async () => {
    const result = await adapterUploadthingAdapter.create(
      {
        secretId: "main",
        adapter: "uploadthing",
        metadata: {},
        io: mockIO({ interactive: false }),
      },
      mockCtx,
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("unsupported");
    expect(result.error?.provider).toBe("UploadThing");
  });
});

describe("adapter-uploadthing.verify", () => {
  test("calls the cheap UploadThing listing endpoint with x-api-key", async () => {
    mockFetch(() => new Response(JSON.stringify({ files: [] }), { status: 200 }));
    const secret: Secret = {
      id: "new",
      provider: "uploadthing",
      value: "ut_new",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterUploadthingAdapter.verify(secret, mockCtx);

    expect(result.ok).toBe(true);
    expect(calls[0]?.url).toMatch(/\/v6\/listFiles$/);
    expect((calls[0]?.init?.headers as Record<string, string>)?.["x-api-key"]).toBe("ut_new");
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const secret: Secret = {
      id: "new",
      provider: "uploadthing",
      value: "ut_new",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterUploadthingAdapter.verify(secret, mockCtx);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });
});

describe("adapter-uploadthing.revoke", () => {
  test("returns ok once the user confirms dashboard revocation", async () => {
    const secret: Secret = {
      id: "old",
      provider: "uploadthing",
      value: tokenWithAppId("app_123"),
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterUploadthingAdapter.revoke(secret, mockCtx, {
      io: mockIO({ confirm: true }),
    });

    expect(result.ok).toBe(true);
  });

  test("non-interactive IO returns unsupported", async () => {
    const secret: Secret = {
      id: "old",
      provider: "uploadthing",
      value: "ut_old",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterUploadthingAdapter.revoke(secret, mockCtx, {
      io: mockIO({ interactive: false }),
    });

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("unsupported");
  });
});

describe("adapter-uploadthing.auth", () => {
  test("resolves modern env auth through shared auth registry", async () => {
    process.env.UPLOADTHING_TOKEN = "ut_env";
    const ctx = await adapterUploadthingAdapter.auth();
    expect(ctx.kind).toBe("env");
    expect(ctx.kind === "env" ? ctx.varName : undefined).toBe("UPLOADTHING_TOKEN");
    expect(ctx.token).toBe("ut_env");
  });

  test("registers auth definition with the adapter", () => {
    expect(getAuthDefinition("uploadthing")?.displayName).toBe("UploadThing");
    expect(getAuthDefinition("uploadthing")?.envVars).toContain("UPLOADTHING_APP_ID");
  });
});

describe("adapter-uploadthing.ownedBy", () => {
  test("returns self when decoded app id matches co-located app id", async () => {
    const result = await adapterUploadthingAdapter.ownedBy?.(tokenWithAppId("app_123"), mockCtx, {
      coLocatedVars: { UPLOADTHING_APP_ID: "app_123" },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.adminCanBill).toBe(true);
    expect(result?.confidence).toBe("medium");
    expect(result?.strategy).toBe("format-decode");
  });

  test("returns self when decoded app id matches future preload apps", async () => {
    const result = await adapterUploadthingAdapter.ownedBy?.(tokenWithAppId("app_123"), mockCtx, {
      preload: { apps: [{ id: "app_123", name: "Production" }] },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.strategy).toBe("format-decode");
  });

  test("uses sibling inheritance for legacy secret with app id sibling", async () => {
    const result = await adapterUploadthingAdapter.ownedBy?.("legacy_secret", mockCtx, {
      coLocatedVars: { UPLOADTHING_APP_ID: "app_123" },
    });

    expect(result?.verdict).toBe("self");
    expect(result?.confidence).toBe("low");
    expect(result?.strategy).toBe("sibling-inheritance");
  });

  test("returns unknown when no app id strategy applies", async () => {
    const result = await adapterUploadthingAdapter.ownedBy?.("legacy_secret", mockCtx);

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
  });
});
