import { describe, it, expect } from "bun:test";
import { MemoryAdapter, useMemoryAdapter } from "../src/index.ts";
import { createMizan } from "@mizan/core";

describe("Memory adapter integration", () => {
  it("useMemoryAdapter registers the memory source on the Mizan instance", () => {
    const mizan = createMizan();
    const adapter = new MemoryAdapter();
    useMemoryAdapter(mizan, adapter);

    // Should not throw when creating an evaluator
    const auth = mizan.forPrincipal("user-1");
    expect(auth).toBeDefined();
  });

  it("complete principal-to-memory-source-to-decision path – allow", async () => {
    const mizan = createMizan();
    const adapter = new MemoryAdapter({
      facts: [{ permission: "files.read", effect: "grant" }],
    });
    useMemoryAdapter(mizan, adapter);

    const auth = mizan.forPrincipal("user-1");
    expect(await auth.can("files.read")).toBe(true);

    const result = await auth.decide("files.read");
    expect(result.decision).toBe("allow");
    expect(result.reason).toBeNull();
  });

  it("complete principal-to-memory-source-to-decision path – deny by matching denial", async () => {
    const mizan = createMizan();
    const adapter = new MemoryAdapter({
      facts: [{ permission: "files.delete", effect: "deny" }],
    });
    useMemoryAdapter(mizan, adapter);

    const auth = mizan.forPrincipal("user-1");
    expect(await auth.can("files.delete")).toBe(false);

    const result = await auth.decide("files.delete");
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("matching-denial");
  });

  it("complete principal-to-memory-source-to-decision path – deny by default", async () => {
    const mizan = createMizan();
    const adapter = new MemoryAdapter({
      facts: [{ permission: "files.read", effect: "grant" }],
    });
    useMemoryAdapter(mizan, adapter);

    const auth = mizan.forPrincipal("user-1");
    expect(await auth.can("files.write")).toBe(false);

    const result = await auth.decide("files.write");
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("no-grant");
  });

  it("denial overrides grant in memory adapter", async () => {
    const mizan = createMizan();
    const adapter = new MemoryAdapter({
      facts: [
        { permission: "files.read", effect: "grant" },
        { permission: "files.read", effect: "deny" },
      ],
    });
    useMemoryAdapter(mizan, adapter);

    const auth = mizan.forPrincipal("user-1");
    expect(await auth.can("files.read")).toBe(false);
  });

  it("grant from role assignment is evaluated", async () => {
    const mizan = createMizan();
    const adapter = new MemoryAdapter({
      roles: [
        {
          name: "editor",
          permissions: [{ permission: "files.write", effect: "grant" }],
        },
      ],
      assignments: [
        { principalId: "user-1", roleName: "editor" },
      ],
    });
    useMemoryAdapter(mizan, adapter);

    const auth = mizan.forPrincipal("user-1");
    expect(await auth.can("files.write")).toBe(true);
  });

  it("memory adapter does not expose final allow/deny - core decides", async () => {
    const adapter = new MemoryAdapter({
      facts: [{ permission: "files.read", effect: "grant" }],
    });

    // The adapter only returns facts, not a decision
    const outcome = await adapter.resolve({ principalId: "user-1" });
    expect(outcome.status).toBe("facts");
    expect(outcome.facts).toHaveLength(1);
    expect(outcome.facts[0]!.effect).toBe("grant");

    // Verify that outcome doesn't contain any decision-like field
    expect("decision" in outcome).toBe(false);
  });
});
