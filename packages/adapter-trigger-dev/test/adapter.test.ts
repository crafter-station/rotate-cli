import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getAuthDefinition } from "@rotate/core/auth";
import { registerAdapter, resetRegistry } from "@rotate/core/registry";
import type { AuthContext, PromptChoice, PromptIO, Secret } from "@rotate/core/types";
import { adapterTriggerDevAdapter } from "../src/index.ts";

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
  registerAdapter(adapterTriggerDevAdapter);
  delete process.env.TRIGGER_SECRET_KEY;
  delete process.env.TRIGGER_API_URL;
  delete process.env.TRIGGER_DEV_API_URL;
});

afterEach(() => {
  global.fetch = originalFetch;
  resetRegistry();
  delete process.env.TRIGGER_SECRET_KEY;
  delete process.env.TRIGGER_API_URL;
  delete process.env.TRIGGER_DEV_API_URL;
});

const mockCtx: AuthContext = {
  kind: "env",
  varName: "TRIGGER_SECRET_KEY",
  token: "tr_dev_old",
};

function makeIO(secret = "tr_dev_new", confirmed = true): PromptIO & { notes: string[] } {
  return {
    isInteractive: true,
    notes: [],
    note(message: string) {
      this.notes.push(message);
    },
    async promptLine(_message: string) {
      return "";
    },
    async promptSecret(_message: string) {
      return secret;
    },
    async select(_message: string, choices: PromptChoice[]) {
      return choices[0]?.value ?? "";
    },
    async confirm(_message: string) {
      return confirmed;
    },
    async close() {},
  };
}

describe("adapter-trigger-dev.create", () => {
  test("uses PromptIO and returns pasted secret", async () => {
    const io = makeIO();
    const result = await adapterTriggerDevAdapter.create(
      {
        secretId: "main",
        adapter: "trigger-dev",
        metadata: { project_ref: "proj_123", environment: "prod" },
        io,
      },
      mockCtx,
    );

    expect(result.ok).toBe(true);
    expect(result.data?.value).toBe("tr_dev_new");
    expect(result.data?.provider).toBe("trigger-dev");
    expect(result.data?.metadata.project_ref).toBe("proj_123");
    expect(result.data?.metadata.environment).toBe("prod");
    expect(result.data?.metadata.rotation_mode).toBe("manual-assist");
    expect(io.notes[0]).toContain("project_ref=proj_123");
    expect(calls).toHaveLength(0);
  });

  test("returns unsupported without interactive IO", async () => {
    const result = await adapterTriggerDevAdapter.create(
      {
        secretId: "main",
        adapter: "trigger-dev",
        metadata: {},
      },
      mockCtx,
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("unsupported");
  });
});

describe("adapter-trigger-dev.verify", () => {
  test("checks the read-only query schema endpoint with the candidate key", async () => {
    mockFetch(() => new Response(JSON.stringify({ tables: [] }), { status: 200 }));
    const secret: Secret = {
      id: "main",
      provider: "trigger-dev",
      value: "tr_dev_new",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterTriggerDevAdapter.verify(secret, mockCtx);

    expect(result.ok).toBe(true);
    expect(calls[0]?.url).toBe("https://api.trigger.dev/api/v1/query/schema");
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer tr_dev_new",
    );
  });

  test("maps 401 to auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const secret: Secret = {
      id: "main",
      provider: "trigger-dev",
      value: "tr_dev_bad",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterTriggerDevAdapter.verify(secret, mockCtx);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });

  test("maps 429 to rate_limited", async () => {
    mockFetch(() => new Response("rate limited", { status: 429 }));
    const secret: Secret = {
      id: "main",
      provider: "trigger-dev",
      value: "tr_dev_rate_limited",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterTriggerDevAdapter.verify(secret, mockCtx);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("rate_limited");
  });

  test("maps 5xx to provider_error", async () => {
    mockFetch(() => new Response("unavailable", { status: 503 }));
    const secret: Secret = {
      id: "main",
      provider: "trigger-dev",
      value: "tr_dev_unavailable",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterTriggerDevAdapter.verify(secret, mockCtx);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("provider_error");
  });
});

describe("adapter-trigger-dev.revoke", () => {
  test("requires dashboard confirmation", async () => {
    const io = makeIO("tr_dev_new", true);
    const secret: Secret = {
      id: "main",
      provider: "trigger-dev",
      value: "tr_dev_old",
      metadata: { project_ref: "proj_123", environment: "prod" },
      createdAt: new Date().toISOString(),
    };

    const result = await adapterTriggerDevAdapter.revoke(secret, mockCtx, { io });

    expect(result.ok).toBe(true);
    expect(io.notes[0]).toContain("project_ref=proj_123");
    expect(calls).toHaveLength(0);
  });

  test("returns unsupported without interactive IO", async () => {
    const secret: Secret = {
      id: "main",
      provider: "trigger-dev",
      value: "tr_dev_old",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterTriggerDevAdapter.revoke(secret, mockCtx);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("unsupported");
  });
});

describe("adapter-trigger-dev.auth", () => {
  test("resolves env auth through shared auth registry", async () => {
    process.env.TRIGGER_SECRET_KEY = "tr_dev_env";
    const ctx = await adapterTriggerDevAdapter.auth();

    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("tr_dev_env");
  });

  test("registers auth definition with the adapter", () => {
    const definition = getAuthDefinition("trigger-dev");

    expect(definition?.displayName).toBe("Trigger.dev");
    expect(definition?.envVars).toEqual(["TRIGGER_SECRET_KEY", "TRIGGER_ACCESS_TOKEN"]);
  });
});

describe("adapter-trigger-dev.ownedBy", () => {
  test("returns unknown without introspection", async () => {
    const result = await adapterTriggerDevAdapter.ownedBy?.("tr_dev_value", mockCtx);

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
  });

  test("preserves project hints as low-confidence sibling evidence", async () => {
    const result = await adapterTriggerDevAdapter.ownedBy?.("tr_dev_value", mockCtx, {
      coLocatedVars: {
        TRIGGER_PROJECT_REF: "proj_123",
        TRIGGER_ENVIRONMENT: "prod",
      },
    });

    expect(result?.verdict).toBe("unknown");
    expect(result?.scope).toBe("project");
    expect(result?.strategy).toBe("sibling-inheritance");
    expect(result?.evidence).toContain("proj_123");
  });
});
