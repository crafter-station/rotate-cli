import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadConfig,
  loadIncident,
  parseDuration,
  selectByIncident,
  selectByQuery,
} from "../src/config.ts";

function tmpFile(name: string, content: string) {
  const dir = mkdtempSync(join(tmpdir(), "rotate-cli-cfg-"));
  const p = join(dir, name);
  writeFileSync(p, content, "utf8");
  return p;
}

describe("config.loadConfig", () => {
  test("parses valid yaml", () => {
    const p = tmpFile(
      "rotate.config.yaml",
      `version: 1
secrets:
  - id: clerk-hack0
    adapter: clerk
    metadata:
      instance_id: ins_abc
    consumers:
      - type: vercel-env
        params:
          project: hack0
          var_name: CLERK_SECRET_KEY
`,
    );
    // loadConfig reads relative to cwd; use absolute here.
    const config = loadConfig(p);
    expect(config.version).toBe(1);
    expect(config.secrets).toHaveLength(1);
    expect(config.secrets[0]?.id).toBe("clerk-hack0");
  });

  test("rejects missing version", () => {
    const p = tmpFile("rotate.config.yaml", "secrets: []");
    expect(() => loadConfig(p)).toThrow();
  });
});

describe("config.selectByQuery", () => {
  const config = {
    version: 1 as const,
    secrets: [
      { id: "a", adapter: "clerk", metadata: {}, consumers: [], tags: ["production"] },
      { id: "b", adapter: "openai", metadata: {}, consumers: [], tags: ["production"] },
      { id: "c", adapter: "openai", metadata: {}, consumers: [], tags: ["staging"] },
    ],
  };

  test("filters by id", () => {
    const r = selectByQuery(config, { ids: ["a"] });
    expect(r).toHaveLength(1);
    expect(r[0]?.id).toBe("a");
  });
  test("filters by canonical id (provider/id)", () => {
    const r = selectByQuery(config, { ids: ["openai/b"] });
    expect(r).toHaveLength(1);
  });
  test("filters by provider", () => {
    const r = selectByQuery(config, { provider: "openai" });
    expect(r).toHaveLength(2);
  });
  test("filters by tag", () => {
    const r = selectByQuery(config, { tag: "staging" });
    expect(r).toHaveLength(1);
  });
  test("combines provider + tag", () => {
    const r = selectByQuery(config, { provider: "openai", tag: "production" });
    expect(r).toHaveLength(1);
    expect(r[0]?.id).toBe("b");
  });
});

describe("config.selectByIncident", () => {
  test("matches provider scope", () => {
    const config = {
      version: 1 as const,
      secrets: [
        { id: "a", adapter: "clerk", metadata: {}, consumers: [] },
        { id: "b", adapter: "openai", metadata: {}, consumers: [] },
      ],
    };
    const incident = {
      version: 1 as const,
      id: "test",
      scope: [{ provider: "clerk" }],
    };
    const r = selectByIncident(config, incident);
    expect(r).toHaveLength(1);
    expect(r[0]?.adapter).toBe("clerk");
  });

  test("respects tag filter", () => {
    const config = {
      version: 1 as const,
      secrets: [
        { id: "a", adapter: "clerk", metadata: {}, tags: ["non-sensitive"], consumers: [] },
        { id: "b", adapter: "clerk", metadata: {}, tags: ["sensitive"], consumers: [] },
      ],
    };
    const incident = {
      version: 1 as const,
      id: "test",
      scope: [{ provider: "clerk", filter: { tag: "non-sensitive" } }],
    };
    const r = selectByIncident(config, incident);
    expect(r).toHaveLength(1);
    expect(r[0]?.id).toBe("a");
  });
});

describe("config.loadIncident", () => {
  test("parses valid incident", () => {
    const p = tmpFile(
      "incident.yaml",
      `version: 1
id: vercel-apr-2026
severity: high
scope:
  - provider: clerk
    filter:
      tag: non-sensitive
`,
    );
    const i = loadIncident(p);
    expect(i.id).toBe("vercel-apr-2026");
    expect(i.scope).toHaveLength(1);
  });
});

describe("config.parseDuration", () => {
  test.each([
    ["100ms", 100],
    ["5s", 5_000],
    ["10m", 600_000],
    ["2h", 7_200_000],
    ["1d", 86_400_000],
  ] as const)("parses %s", (input, expected) => {
    expect(parseDuration(input)).toBe(expected);
  });
  test("rejects garbage", () => {
    expect(() => parseDuration("foo")).toThrow();
  });
});
