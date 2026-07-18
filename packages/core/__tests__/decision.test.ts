import { describe, it, expect } from "bun:test";
import {
  createMizan,
  Mizan,
  PrincipalEvaluator,
  type SourceResolver,
  type AuthorizationFact,
} from "../src/index.ts";

// ─── Helpers ───────────────────────────────────────────────────────────────

function sourceWith(...facts: AuthorizationFact[]): SourceResolver {
  return {
    async resolve() {
      return { status: "facts", facts, freshness: "fresh" };
    },
  };
}

function emptySource(): SourceResolver {
  return {
    async resolve() {
      return { status: "facts", facts: [], freshness: "fresh" };
    },
  };
}

// ─── PrincipalEvaluator: can() ─────────────────────────────────────────────

describe("PrincipalEvaluator.can()", () => {
  it("returns true for exact matching grant", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "files.read", effect: "grant" }));
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(true);
  });

  it("returns false for exact matching denial", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "files.delete", effect: "deny" }));
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.delete")).toBe(false);
  });

  it("returns false when no facts match (deny-by-default)", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "files.read", effect: "grant" }));
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.write")).toBe(false);
  });

  it("denial overrides grant for the same permission", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        { permission: "files.read", effect: "grant" },
        { permission: "files.read", effect: "deny" },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    // Denial should override grant
    expect(await auth.can("files.read")).toBe(false);
  });

  it("does not affect unrelated permissions", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        { permission: "files.read", effect: "grant" },
        { permission: "files.delete", effect: "deny" },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(true);
    expect(await auth.can("files.delete")).toBe(false);
    expect(await auth.can("files.write")).toBe(false);
  });

  it("merges facts from multiple sources", async () => {
    const mizan = createMizan();
    mizan.registerSource("srcA", sourceWith({ permission: "files.read", effect: "grant" }));
    mizan.registerSource("srcB", sourceWith({ permission: "files.write", effect: "grant" }));
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(true);
    expect(await auth.can("files.write")).toBe(true);
  });

  it("denial overrides grant even across sources", async () => {
    const mizan = createMizan();
    mizan.registerSource("srcA", sourceWith({ permission: "files.read", effect: "grant" }));
    mizan.registerSource("srcB", sourceWith({ permission: "files.read", effect: "deny" }));
    const auth = mizan.forPrincipal("user-1");

    // Denial from srcB overrides grant from srcA
    expect(await auth.can("files.read")).toBe(false);
  });

  it("empty facts produce deny", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", emptySource());
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("anything")).toBe(false);
  });
});

// ─── PrincipalEvaluator: decide() ──────────────────────────────────────────

describe("PrincipalEvaluator.decide()", () => {
  it("returns allow with null reason for a matching grant", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "files.read", effect: "grant" }));
    const auth = mizan.forPrincipal("user-1");

    const result = await auth.decide("files.read");
    expect(result.decision).toBe("allow");
    expect(result.reason).toBeNull();
  });

  it("returns deny with matching-denial reason for a matching denial", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "files.delete", effect: "deny" }));
    const auth = mizan.forPrincipal("user-1");

    const result = await auth.decide("files.delete");
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("matching-denial");
  });

  it("returns deny with no-grant reason when no facts match", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "files.read", effect: "grant" }));
    const auth = mizan.forPrincipal("user-1");

    const result = await auth.decide("nonexistent");
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("no-grant");
  });

  it("returns deny with matching-denial when denial overrides grant", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "files.read", effect: "grant" }, { permission: "files.read", effect: "deny" }));
    const auth = mizan.forPrincipal("user-1");

    const result = await auth.decide("files.read");
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("matching-denial");
  });

  it("does not throw for expected outcomes", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", emptySource());
    const auth = mizan.forPrincipal("user-1");

    expect(async () => await auth.can("anything")).not.toThrow();
    expect(async () => await auth.decide("anything")).not.toThrow();
  });
});

// ─── Configuration errors ──────────────────────────────────────────────────

describe("Configuration errors", () => {
  it("throws when no sources are registered and can is called", async () => {
    const mizan = createMizan();
    const auth = mizan.forPrincipal("user-1");

    expect(auth.can("anything")).rejects.toThrow(/no sources registered/i);
  });

  it("throws when a source resolves with malformed status", async () => {
    const mizan = createMizan();
    mizan.registerSource("bad", {
      async resolve() {
        // @ts-expect-error — intentionally malformed
        return { status: "garbage", facts: [] };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    expect(auth.can("x")).rejects.toThrow(/contract violation/i);
  });
});

// ─── Principal binding ─────────────────────────────────────────────────────

describe("forPrincipal()", () => {
  it("returns a PrincipalEvaluator bound to the given principal", () => {
    const mizan = createMizan();
    const auth = mizan.forPrincipal("user-42");
    expect(auth).toBeInstanceOf(PrincipalEvaluator);
  });
});

// ─── Mizan class API ───────────────────────────────────────────────────────

describe("Mizan", () => {
  it("registerSource stores a resolver", () => {
    const mizan = createMizan();
    const resolver: SourceResolver = emptySource();
    mizan.registerSource("test", resolver);
    // No throw means success
  });

  it("can be exported and instantiated", () => {
    const mizan = new Mizan();
    expect(mizan).toBeDefined();
  });
});
