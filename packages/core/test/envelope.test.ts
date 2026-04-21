import { describe, expect, test } from "bun:test";
import { envelopeJsonSchema, makeEnvelope } from "../src/envelope.ts";

describe("envelope", () => {
  test("makeEnvelope produces valid shape", () => {
    const e = makeEnvelope({
      command: "apply",
      status: "success",
      startedAt: Date.now() - 100,
      data: { hello: "world" },
    });
    expect(e.version).toBe("1");
    expect(e.command).toBe("apply");
    expect(e.errors).toEqual([]);
    expect(e.next_actions).toEqual([]);
    expect(e.meta.agent_mode).toBe(false);
    expect(e.meta.duration_ms).toBeGreaterThanOrEqual(0);
  });

  test("schema is stable", () => {
    expect(envelopeJsonSchema.type).toBe("object");
    expect(envelopeJsonSchema.required).toContain("version");
  });
});
