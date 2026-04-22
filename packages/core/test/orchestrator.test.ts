import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyRotation, preloadOwnershipForSecrets, revokeRotation } from "../src/orchestrator.ts";
import { registerAdapter, registerConsumer, resetRegistry } from "../src/registry.ts";
import type {
  Adapter,
  AuthContext,
  Consumer,
  ConsumerTarget,
  RotationSpec,
  Secret,
} from "../src/types.ts";

const mockSecretValue = () => `sk_live_${Math.random().toString(36).slice(2)}`;

function makeMockAdapter(): Adapter {
  let created: Secret | undefined;
  let revoked = false;
  return {
    name: "mock-provider",
    async auth(): Promise<AuthContext> {
      return { kind: "env", varName: "MOCK", token: "mock-token" };
    },
    async create(spec: RotationSpec) {
      created = {
        id: "key_123",
        provider: "mock-provider",
        value: mockSecretValue(),
        metadata: { ...spec.metadata },
        createdAt: new Date().toISOString(),
      };
      return { ok: true, data: created };
    },
    async verify(secret: Secret) {
      return { ok: secret.value.startsWith("sk_live_"), data: true };
    },
    async revoke() {
      revoked = true;
      return { ok: true, data: undefined };
    },
    async list() {
      return { ok: true, data: created ? [created] : [] };
    },
  };
}

function makeMockConsumer(name = "mock-consumer"): Consumer {
  const stored = new Map<string, string>();
  return {
    name,
    async auth(): Promise<AuthContext> {
      return { kind: "env", varName: "MOCK_CONSUMER", token: "mock" };
    },
    async propagate(target: ConsumerTarget, secret: Secret) {
      const key = `${target.params.project}:${target.params.var_name}`;
      stored.set(key, secret.value);
      return { ok: true, data: undefined };
    },
    async trigger() {
      return { ok: true, data: undefined };
    },
    async verify(target: ConsumerTarget, secret: Secret) {
      const key = `${target.params.project}:${target.params.var_name}`;
      return { ok: true, data: stored.get(key) === secret.value };
    },
  };
}

describe("orchestrator.applyRotation", () => {
  let stateDir: string;
  beforeEach(() => {
    resetRegistry();
    stateDir = mkdtempSync(join(tmpdir(), "rotate-cli-test-"));
    process.env.ROTATE_CLI_STATE_DIR = stateDir;
  });
  afterEach(() => {
    rmSync(stateDir, { recursive: true, force: true });
    delete process.env.ROTATE_CLI_STATE_DIR;
  });

  test("full happy-path rotation with 2 consumers", async () => {
    registerAdapter(makeMockAdapter());
    registerConsumer(makeMockConsumer("mock-consumer"));

    const { rotation, envelopeStatus } = await applyRotation(
      {
        id: "primary",
        adapter: "mock-provider",
        metadata: { instance_id: "ins_test" },
        consumers: [
          { type: "mock-consumer", params: { project: "hack0", var_name: "API_KEY" } },
          { type: "mock-consumer", params: { project: "tinte", var_name: "API_KEY" } },
        ],
      },
      { reason: "unit test" },
    );

    expect(envelopeStatus).toBe("success");
    expect(rotation.status).toBe("in_grace");
    expect(rotation.newSecret?.value).toMatch(/^sk_live_/);
    expect(rotation.consumers).toHaveLength(2);
    for (const c of rotation.consumers) {
      expect(c.status).toBe("synced");
    }
    expect(rotation.gracePeriodEndsAt).toBeTruthy();
  });

  test("partial success when one consumer fails", async () => {
    registerAdapter(makeMockAdapter());
    const failingConsumer: Consumer = {
      name: "failing-consumer",
      async auth(): Promise<AuthContext> {
        return { kind: "env", varName: "X", token: "x" };
      },
      async propagate() {
        return {
          ok: false,
          error: {
            code: "provider_error",
            message: "simulated failure",
            provider: "failing-consumer",
            retryable: true,
          },
        };
      },
    };
    registerConsumer(makeMockConsumer("mock-consumer"));
    registerConsumer(failingConsumer);

    const { rotation, envelopeStatus } = await applyRotation(
      {
        id: "primary",
        adapter: "mock-provider",
        metadata: { instance_id: "ins_test" },
        consumers: [
          { type: "mock-consumer", params: { project: "hack0", var_name: "API_KEY" } },
          { type: "failing-consumer", params: { project: "broken", var_name: "API_KEY" } },
        ],
      },
      { reason: "partial test" },
    );

    expect(envelopeStatus).toBe("partial");
    expect(rotation.consumers[0]?.status).toBe("synced");
    expect(rotation.consumers[1]?.status).toBe("failed");
  });
});

describe("orchestrator.revokeRotation", () => {
  let stateDir: string;
  beforeEach(() => {
    resetRegistry();
    stateDir = mkdtempSync(join(tmpdir(), "rotate-cli-test-"));
    process.env.ROTATE_CLI_STATE_DIR = stateDir;
  });
  afterEach(() => {
    rmSync(stateDir, { recursive: true, force: true });
    delete process.env.ROTATE_CLI_STATE_DIR;
  });

  test("revoke blocked when not fully synced and not forced", async () => {
    const adapter = makeMockAdapter();
    registerAdapter(adapter);
    registerConsumer(makeMockConsumer());
    const { rotation } = await applyRotation({
      id: "primary",
      adapter: "mock-provider",
      metadata: {},
      consumers: [{ type: "mock-consumer", params: { project: "p", var_name: "K" } }],
    });
    // Simulate a pending consumer.
    rotation.consumers[0]!.status = "propagated";
    rotation.oldSecret = { ...rotation.newSecret!, id: "old_key" };

    const result = await revokeRotation(rotation);
    expect(result.ok).toBe(false);
  });

  test("revoke succeeds with force", async () => {
    const adapter = makeMockAdapter();
    registerAdapter(adapter);
    registerConsumer(makeMockConsumer());
    const { rotation } = await applyRotation({
      id: "primary",
      adapter: "mock-provider",
      metadata: {},
      consumers: [{ type: "mock-consumer", params: { project: "p", var_name: "K" } }],
    });
    rotation.oldSecret = { ...rotation.newSecret!, id: "old_key" };

    const result = await revokeRotation(rotation, { force: true });
    expect(result.ok).toBe(true);
    expect(rotation.status).toBe("revoked");
  });
});

function makeMockAdapterWithOwnership(
  verdict: "self" | "other" | "unknown",
  adminCanBill = true,
): Adapter {
  const base = makeMockAdapter();
  return {
    ...base,
    async ownedBy(_v: string, _ctx: AuthContext) {
      return {
        verdict,
        adminCanBill,
        confidence: "high" as const,
        evidence: `mock ${verdict}`,
        strategy: "api-introspection" as const,
      };
    },
  };
}

describe("orchestrator.applyRotation ownership gate", () => {
  let stateDir: string;
  beforeEach(() => {
    resetRegistry();
    stateDir = mkdtempSync(join(tmpdir(), "rotate-cli-test-"));
    process.env.ROTATE_CLI_STATE_DIR = stateDir;
  });
  afterEach(() => {
    rmSync(stateDir, { recursive: true, force: true });
    delete process.env.ROTATE_CLI_STATE_DIR;
  });

  test("skips when ownedBy returns other", async () => {
    registerAdapter(makeMockAdapterWithOwnership("other"));
    registerConsumer(makeMockConsumer("mock-consumer"));

    const { rotation, envelopeStatus } = await applyRotation(
      {
        id: "primary",
        adapter: "mock-provider",
        metadata: {},
        consumers: [{ type: "mock-consumer", params: { project: "p", var_name: "K" } }],
      },
      { currentValue: "sk-current" },
    );

    expect(envelopeStatus).toBe("skipped");
    expect(rotation.status).toBe("skipped");
    expect(rotation.skipReason?.kind).toBe("ownership-other");
    expect(rotation.newSecret).toBeUndefined();
  });

  test("skips self + not-admin-billable", async () => {
    registerAdapter(makeMockAdapterWithOwnership("self", false));
    registerConsumer(makeMockConsumer("mock-consumer"));

    const { rotation, envelopeStatus } = await applyRotation(
      {
        id: "primary",
        adapter: "mock-provider",
        metadata: {},
        consumers: [{ type: "mock-consumer", params: { project: "p", var_name: "K" } }],
      },
      { currentValue: "sk-current" },
    );

    expect(envelopeStatus).toBe("skipped");
    expect(rotation.skipReason?.kind).toBe("ownership-self-member-only");
  });

  test("proceeds when self + adminCanBill=true", async () => {
    registerAdapter(makeMockAdapterWithOwnership("self", true));
    registerConsumer(makeMockConsumer("mock-consumer"));

    const { rotation, envelopeStatus } = await applyRotation(
      {
        id: "primary",
        adapter: "mock-provider",
        metadata: {},
        consumers: [{ type: "mock-consumer", params: { project: "p", var_name: "K" } }],
      },
      { currentValue: "sk-current" },
    );

    expect(envelopeStatus).toBe("success");
    expect(rotation.status).toBe("in_grace");
    expect(rotation.newSecret?.value).toMatch(/^sk_live_/);
    expect(rotation.ownership?.verdict).toBe("self");
  });

  test("proceeds on unknown by default", async () => {
    registerAdapter(makeMockAdapterWithOwnership("unknown"));
    registerConsumer(makeMockConsumer("mock-consumer"));

    const { rotation, envelopeStatus } = await applyRotation(
      {
        id: "primary",
        adapter: "mock-provider",
        metadata: {},
        consumers: [{ type: "mock-consumer", params: { project: "p", var_name: "K" } }],
      },
      { currentValue: "sk-current" },
    );

    expect(envelopeStatus).toBe("success");
    expect(rotation.status).toBe("in_grace");
  });

  test("skips unknown when --skip-unknown", async () => {
    registerAdapter(makeMockAdapterWithOwnership("unknown"));
    registerConsumer(makeMockConsumer("mock-consumer"));

    const { rotation, envelopeStatus } = await applyRotation(
      {
        id: "primary",
        adapter: "mock-provider",
        metadata: {},
        consumers: [{ type: "mock-consumer", params: { project: "p", var_name: "K" } }],
      },
      { currentValue: "sk-current", skipUnknown: true },
    );

    expect(envelopeStatus).toBe("skipped");
    expect(rotation.skipReason?.kind).toBe("ownership-unknown-skipped");
  });

  test("proceeds with --force-rotate-other even if other", async () => {
    registerAdapter(makeMockAdapterWithOwnership("other"));
    registerConsumer(makeMockConsumer("mock-consumer"));

    const { rotation, envelopeStatus } = await applyRotation(
      {
        id: "primary",
        adapter: "mock-provider",
        metadata: {},
        consumers: [{ type: "mock-consumer", params: { project: "p", var_name: "K" } }],
      },
      { currentValue: "sk-current", forceRotateOther: true },
    );

    expect(envelopeStatus).toBe("success");
    expect(rotation.ownership?.verdict).toBe("other");
  });

  test("adapter without ownedBy skips the gate entirely", async () => {
    registerAdapter(makeMockAdapter()); // no ownedBy
    registerConsumer(makeMockConsumer("mock-consumer"));

    const { rotation, envelopeStatus } = await applyRotation(
      {
        id: "primary",
        adapter: "mock-provider",
        metadata: {},
        consumers: [{ type: "mock-consumer", params: { project: "p", var_name: "K" } }],
      },
      { currentValue: "sk-current" },
    );

    expect(envelopeStatus).toBe("success");
    expect(rotation.ownership).toBeUndefined();
  });

  test("preloadOwnershipForSecrets calls preload once per unique adapter", async () => {
    let calls = 0;
    const makeAdapter = (name: string): Adapter => ({
      ...makeMockAdapter(),
      name,
      async preloadOwnership() {
        calls++;
        return { adapter: name };
      },
    });
    registerAdapter(makeAdapter("adapter-a"));
    registerAdapter(makeAdapter("adapter-b"));

    const { map, errors } = await preloadOwnershipForSecrets([
      { id: "1", adapter: "adapter-a", metadata: {}, consumers: [] },
      { id: "2", adapter: "adapter-a", metadata: {}, consumers: [] },
      { id: "3", adapter: "adapter-b", metadata: {}, consumers: [] },
    ]);

    expect(calls).toBe(2);
    expect(map.size).toBe(2);
    expect(errors.size).toBe(0);
    expect((map.get("adapter-a") as { adapter: string }).adapter).toBe("adapter-a");
  });

  test("preloadOwnershipForSecrets captures errors per-adapter without aborting", async () => {
    const good: Adapter = {
      ...makeMockAdapter(),
      name: "good",
      async preloadOwnership() {
        return { ok: true };
      },
    };
    const bad: Adapter = {
      ...makeMockAdapter(),
      name: "bad",
      async preloadOwnership() {
        throw new Error("boom");
      },
    };
    registerAdapter(good);
    registerAdapter(bad);

    const { map, errors } = await preloadOwnershipForSecrets([
      { id: "1", adapter: "good", metadata: {}, consumers: [] },
      { id: "2", adapter: "bad", metadata: {}, consumers: [] },
    ]);

    expect(map.has("good")).toBe(true);
    expect(errors.get("bad")).toContain("boom");
  });

  test("unavailable currentValue + skipUnknown → skip", async () => {
    registerAdapter(makeMockAdapterWithOwnership("self"));
    registerConsumer(makeMockConsumer("mock-consumer"));

    const { rotation, envelopeStatus } = await applyRotation(
      {
        id: "primary",
        adapter: "mock-provider",
        metadata: {},
        consumers: [{ type: "mock-consumer", params: { project: "p", var_name: "K" } }],
      },
      { skipUnknown: true }, // no currentValue
    );

    expect(envelopeStatus).toBe("skipped");
    expect(rotation.skipReason?.kind).toBe("ownership-current-value-unavailable");
  });

  test("manual-assist adapter in agent-mode → unsupported error", async () => {
    const adapter = makeMockAdapter();
    (adapter as unknown as { mode: string }).mode = "manual-assist";
    registerAdapter(adapter);
    registerConsumer(makeMockConsumer("mock-consumer"));

    const { envelopeStatus, rotation } = await applyRotation(
      {
        id: "primary",
        adapter: "mock-provider",
        metadata: {},
        consumers: [{ type: "mock-consumer", params: { project: "p", var_name: "K" } }],
      },
      { agentMode: true },
    );

    expect(envelopeStatus).toBe("error");
    expect(rotation.errors[0]?.code).toBe("unsupported");
    expect(rotation.errors[0]?.message).toContain("manual-assist");
  });

  test("manual-assist adapter without interactive IO → unsupported error", async () => {
    const adapter = makeMockAdapter();
    (adapter as unknown as { mode: string }).mode = "manual-assist";
    registerAdapter(adapter);
    registerConsumer(makeMockConsumer("mock-consumer"));

    const { envelopeStatus, rotation } = await applyRotation(
      {
        id: "primary",
        adapter: "mock-provider",
        metadata: {},
        consumers: [{ type: "mock-consumer", params: { project: "p", var_name: "K" } }],
      },
      {}, // no io
    );

    expect(envelopeStatus).toBe("error");
    expect(rotation.errors[0]?.code).toBe("unsupported");
    expect(rotation.errors[0]?.message).toContain("interactive terminal");
  });
});
