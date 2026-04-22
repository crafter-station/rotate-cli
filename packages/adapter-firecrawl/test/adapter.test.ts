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
import { adapterFirecrawlAdapter } from "../src/index.ts";

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

class ScriptedIO implements PromptIO {
  readonly isInteractive: boolean;
  readonly notes: string[] = [];

  constructor(
    private readonly options: {
      interactive?: boolean;
      secrets?: string[];
      confirms?: boolean[];
    } = {},
  ) {
    this.isInteractive = options.interactive ?? true;
  }

  note(message: string): void {
    this.notes.push(message);
  }

  async promptLine(_message: string): Promise<string> {
    return "";
  }

  async promptSecret(_message: string): Promise<string> {
    return this.options.secrets?.shift() ?? "";
  }

  async select(_message: string, choices: PromptChoice[]): Promise<string> {
    return choices[0]?.value ?? "";
  }

  async confirm(_message: string, _options?: PromptConfirmOptions): Promise<boolean> {
    return this.options.confirms?.shift() ?? false;
  }

  async close(): Promise<void> {}
}

beforeEach(() => {
  calls = [];
  resetRegistry();
  registerAdapter(adapterFirecrawlAdapter);
  delete process.env.FIRECRAWL_API_KEY;
});

afterEach(() => {
  global.fetch = originalFetch;
  resetRegistry();
  delete process.env.FIRECRAWL_API_KEY;
});

const mockCtx: AuthContext = {
  kind: "env",
  varName: "FIRECRAWL_API_KEY",
  token: "fc-admin",
};

describe("adapter-firecrawl.create", () => {
  test("prompts for a replacement Firecrawl API key and returns a Secret", async () => {
    const io = new ScriptedIO({ secrets: ["fc-new-key"] });

    const result = await adapterFirecrawlAdapter.create(
      {
        secretId: "firecrawl-main",
        adapter: "firecrawl",
        metadata: { env_var: "FIRECRAWL_API_KEY" },
        io,
      },
      mockCtx,
    );

    expect(result.ok).toBe(true);
    expect(result.data?.id).toBe("firecrawl-main");
    expect(result.data?.provider).toBe("firecrawl");
    expect(result.data?.value).toBe("fc-new-key");
    expect(result.data?.metadata.manual_assist).toBe("true");
    expect(io.notes[0]).toContain("manual-assist");
    expect(calls).toHaveLength(0);
  });

  test("non-interactive IO returns unsupported", async () => {
    const result = await adapterFirecrawlAdapter.create(
      {
        secretId: "firecrawl-main",
        adapter: "firecrawl",
        metadata: {},
        io: new ScriptedIO({ interactive: false }),
      },
      mockCtx,
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("unsupported");
  });
});

describe("adapter-firecrawl.verify", () => {
  test("checks credit usage with the candidate Firecrawl key", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            success: true,
            data: { remainingCredits: 1000, planCredits: 500000 },
          }),
          { status: 200 },
        ),
    );
    const secret: Secret = {
      id: "firecrawl-main",
      provider: "firecrawl",
      value: "fc-new-key",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterFirecrawlAdapter.verify(secret, mockCtx);

    expect(result.ok).toBe(true);
    expect(calls[0]?.url).toBe("https://api.firecrawl.dev/v2/team/credit-usage");
    expect((calls[0]?.init?.headers as Record<string, string>)?.Authorization).toBe(
      "Bearer fc-new-key",
    );
  });

  test("401 becomes auth_failed", async () => {
    mockFetch(() => new Response("unauthorized", { status: 401 }));
    const secret: Secret = {
      id: "firecrawl-main",
      provider: "firecrawl",
      value: "fc-bad-key",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterFirecrawlAdapter.verify(secret, mockCtx);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("auth_failed");
  });

  test("429 becomes rate_limited", async () => {
    mockFetch(() => new Response("rate limited", { status: 429 }));
    const secret: Secret = {
      id: "firecrawl-main",
      provider: "firecrawl",
      value: "fc-key",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterFirecrawlAdapter.verify(secret, mockCtx);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("rate_limited");
  });
});

describe("adapter-firecrawl.revoke", () => {
  test("prints manual cleanup instructions and succeeds after confirmation", async () => {
    const io = new ScriptedIO({ confirms: [true] });
    const secret: Secret = {
      id: "firecrawl-main",
      provider: "firecrawl",
      value: "fc-old-key",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterFirecrawlAdapter.revoke(secret, mockCtx, { io });

    expect(result.ok).toBe(true);
    expect(io.notes[0]).toContain("old API key cleanup");
    expect(calls).toHaveLength(0);
  });

  test("non-interactive IO returns unsupported", async () => {
    const secret: Secret = {
      id: "firecrawl-main",
      provider: "firecrawl",
      value: "fc-old-key",
      metadata: {},
      createdAt: new Date().toISOString(),
    };

    const result = await adapterFirecrawlAdapter.revoke(secret, mockCtx, {
      io: new ScriptedIO({ interactive: false }),
    });

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe("unsupported");
  });
});

describe("adapter-firecrawl.ownedBy", () => {
  test("returns unknown because Firecrawl has no documented ownership endpoint", async () => {
    const result = await adapterFirecrawlAdapter.ownedBy?.("fc-key", mockCtx);

    expect(result?.verdict).toBe("unknown");
    expect(result?.adminCanBill).toBe(false);
    expect(result?.confidence).toBe("low");
    expect(result?.strategy).toBe("api-introspection");
    expect(result?.evidence).toContain("no documented API key introspection");
    expect(calls).toHaveLength(0);
  });
});

describe("adapter-firecrawl.auth", () => {
  test("resolves env auth through shared auth registry", async () => {
    process.env.FIRECRAWL_API_KEY = "fc-env-key";

    const ctx = await adapterFirecrawlAdapter.auth();

    expect(ctx.kind).toBe("env");
    expect(ctx.token).toBe("fc-env-key");
  });

  test("registers auth definition with Firecrawl env vars", () => {
    const definition = getAuthDefinition("firecrawl");

    expect(definition?.displayName).toBe("Firecrawl");
    expect(definition?.envVars).toContain("FIRECRAWL_API_KEY");
  });
});
