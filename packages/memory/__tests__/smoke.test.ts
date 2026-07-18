import { describe, it, expect } from "bun:test";
import { MemoryAdapter, useMemoryAdapter } from "../src/index.ts";
import { createMizan, Mizan } from "@mizan/core";

describe("@mizan/memory", () => {
  it("exports MemoryAdapter", () => {
    expect(MemoryAdapter).toBeInstanceOf(Function);
  });

  it("exports useMemoryAdapter", () => {
    expect(useMemoryAdapter).toBeInstanceOf(Function);
  });

  it("can create an empty MemoryAdapter", () => {
    const adapter = new MemoryAdapter();
    expect(adapter).toBeDefined();
    expect(adapter.sourceName).toBe("memory");
  });

  it("can create a MemoryAdapter with initial facts", () => {
    const adapter = new MemoryAdapter({
      facts: [
        { permission: "files.read", effect: "grant" },
        { permission: "files.delete", effect: "deny" },
      ],
    });
    expect(adapter).toBeDefined();
  });

  it("resolve returns fresh empty facts for empty adapter", async () => {
    const adapter = new MemoryAdapter();
    const outcome = await adapter.resolve({ principalId: "user-1" });
    expect(outcome.status).toBe("facts");
    expect(outcome.facts).toEqual([]);
    expect(outcome.freshness).toBe("fresh");
  });

  it("resolve returns stored facts", async () => {
    const adapter = new MemoryAdapter({
      facts: [{ permission: "files.read", effect: "grant" }],
    });
    const outcome = await adapter.resolve({ principalId: "user-1" });
    expect(outcome.status).toBe("facts");
    expect(outcome.facts).toHaveLength(1);
    expect(outcome.facts[0]!.permission).toBe("files.read");
  });

  it("addFact adds a fact to the store", async () => {
    const adapter = new MemoryAdapter();
    adapter.addFact({ permission: "admin.*", effect: "deny" });

    const outcome = await adapter.resolve({ principalId: "user-1" });
    expect(outcome.facts).toHaveLength(1);
    expect(outcome.facts[0]!.permission).toBe("admin.*");
    expect(outcome.facts[0]!.effect).toBe("deny");
  });

  it("useMemoryAdapter is a no-op placeholder", () => {
    const mizan = createMizan();
    const adapter = new MemoryAdapter();
    // Should not throw
    expect(() => useMemoryAdapter(mizan, adapter)).not.toThrow();
  });

  it("MemoryAdapter can be constructed without config", () => {
    const adapter = new MemoryAdapter();
    expect(adapter).toBeInstanceOf(MemoryAdapter);
  });
});
