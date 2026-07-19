import { describe, it, expect } from "bun:test";
import {
  createMizan,
  Mizan,
  PrincipalEvaluator,
  matchesPermission,
  type SourceResolver,
  type AuthorizationFact,
  type ResolveContext,
  type SourceOutcome,
} from "../src/index.ts";

// ─── Test helpers ───────────────────────────────────────────────────────────

function sourceWith(...facts: AuthorizationFact[]): SourceResolver {
  return {
    async resolve(_ctx: ResolveContext) {
      return { status: "facts", facts, freshness: "fresh" };
    },
  };
}

function emptySource(): SourceResolver {
  return {
    async resolve(_ctx: ResolveContext) {
      return { status: "facts", facts: [], freshness: "fresh" };
    },
  };
}

// ─── matchesPermission() ───────────────────────────────────────────────────

describe("matchesPermission()", () => {
  it("exact match returns true", () => {
    expect(matchesPermission("files.read", "files.read")).toBe(true);
  });

  it("different exact permission returns false", () => {
    expect(matchesPermission("files.read", "files.write")).toBe(false);
  });

  it("global pattern matches everything", () => {
    expect(matchesPermission("anything", "*")).toBe(true);
    expect(matchesPermission("files.read", "*")).toBe(true);
    expect(matchesPermission("admin.view", "*")).toBe(true);
  });

  it("namespace pattern matches permissions under that prefix", () => {
    expect(matchesPermission("files.read", "files.*")).toBe(true);
    expect(matchesPermission("files.write", "files.*")).toBe(true);
    expect(matchesPermission("files.sub.delete", "files.*")).toBe(true);
    expect(matchesPermission("files", "files.*")).toBe(true);
  });

  it("namespace pattern does not match unrelated permissions", () => {
    expect(matchesPermission("admin.view", "files.*")).toBe(false);
    expect(matchesPermission("firefiles.read", "files.*")).toBe(false);
  });

  it("namespace pattern enforces dot boundary (rejects prefix-like names)", () => {
    // "filesX.read" starts with "files" but is outside the "files.*" namespace
    expect(matchesPermission("filesX.read", "files.*")).toBe(false);
  });

  it("empty permission does not match non-global pattern", () => {
    expect(matchesPermission("", "files.*")).toBe(false);
  });
});

// ─── Pattern-based evaluation ─────────────────────────────────────────────

describe("PrincipalEvaluator with patterns", () => {
  it("global grant allows any permission", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "*", effect: "grant" }));
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("anything")).toBe(true);
    expect(await auth.can("files.read")).toBe(true);
    expect(await auth.can("admin.view")).toBe(true);
  });

  it("namespace grant allows permissions under that namespace", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "files.*", effect: "grant" }));
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(true);
    expect(await auth.can("files.write")).toBe(true);
    expect(await auth.can("admin.view")).toBe(false);
  });

  it("namespace denial overrides specific exact grant", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        { permission: "files.read", effect: "grant" },
        { permission: "files.*", effect: "deny" },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(false);
  });

  it("exact denial overrides namespace grant", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        { permission: "files.*", effect: "grant" },
        { permission: "files.delete", effect: "deny" },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(true);
    expect(await auth.can("files.delete")).toBe(false);
  });

  it("global denial overrides any grant", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        { permission: "*", effect: "deny" },
        { permission: "files.read", effect: "grant" },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(false);
    expect(await auth.can("anything")).toBe(false);
  });

  it("pattern does not make missing permission valid (deny-by-default)", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "files.*", effect: "grant" }));
    const auth = mizan.forPrincipal("user-1");

    // Permission not under any matching pattern/namespace
    expect(await auth.can("unknown")).toBe(false);
  });

  it("multiple namespace grants are additive", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        { permission: "files.*", effect: "grant" },
        { permission: "admin.*", effect: "grant" },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(true);
    expect(await auth.can("admin.view")).toBe(true);
    expect(await auth.can("other.action")).toBe(false);
  });

  it("denial from one namespace does not affect another namespace", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        { permission: "files.*", effect: "grant" },
        { permission: "admin.*", effect: "deny" },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(true);
    expect(await auth.can("admin.view")).toBe(false);
  });
});

// ─── Role-derived access integration ───────────────────────────────────────

describe("Role-derived access", () => {
  it("role-derived grants are additive with direct grants", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", {
      async resolve(_context: { principalId?: string }) {
        const roleFacts: AuthorizationFact[] = [
          { permission: "files.read", effect: "grant" },
          { permission: "files.write", effect: "grant" },
        ];
        const directFacts: AuthorizationFact[] = [
          { permission: "admin.view", effect: "grant" },
        ];
        return { status: "facts", facts: [...roleFacts, ...directFacts], freshness: "fresh" };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(true);
    expect(await auth.can("files.write")).toBe(true);
    expect(await auth.can("admin.view")).toBe(true);
  });

  it("direct denial overrides role-derived grant", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", {
      async resolve(_context: { principalId?: string }) {
        const roleFacts: AuthorizationFact[] = [
          { permission: "files.read", effect: "grant" },
        ];
        const directFacts: AuthorizationFact[] = [
          { permission: "files.read", effect: "deny" },
        ];
        return { status: "facts", facts: [...roleFacts, ...directFacts], freshness: "fresh" };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(false);
  });

  it("denying one permission does not remove unrelated permissions", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", {
      async resolve(_context: { principalId?: string }) {
        const roleFacts: AuthorizationFact[] = [
          { permission: "files.read", effect: "grant" },
          { permission: "files.write", effect: "grant" },
        ];
        const directFacts: AuthorizationFact[] = [
          { permission: "files.read", effect: "deny" },
        ];
        return { status: "facts", facts: [...roleFacts, ...directFacts], freshness: "fresh" };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(false);
    expect(await auth.can("files.write")).toBe(true);
  });

  it("role with namespace pattern grants specific permissions", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", {
      async resolve(_context: { principalId?: string }) {
        const roleFacts: AuthorizationFact[] = [
          { permission: "files.*", effect: "grant" },
        ];
        return { status: "facts", facts: roleFacts, freshness: "fresh" };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(true);
    expect(await auth.can("files.write")).toBe(true);
    expect(await auth.can("admin.view")).toBe(false);
  });

  it("multiple roles produce additive grants", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", {
      async resolve(_context: { principalId?: string }) {
        const roleAFacts: AuthorizationFact[] = [
          { permission: "files.*", effect: "grant" },
        ];
        const roleBFacts: AuthorizationFact[] = [
          { permission: "admin.view", effect: "grant" },
        ];
        return { status: "facts", facts: [...roleAFacts, ...roleBFacts], freshness: "fresh" };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(true);
    expect(await auth.can("admin.view")).toBe(true);
  });
});

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

    await expect(auth.can("anything")).resolves.toBe(false);
    await expect(auth.decide("anything")).resolves.toHaveProperty("decision", "deny");
  });
});

// ─── Configuration errors ──────────────────────────────────────────────────

describe("Configuration errors", () => {
  it("throws when no sources are registered and can is called", async () => {
    const mizan = createMizan();
    const auth = mizan.forPrincipal("user-1");

    await expect(auth.can("anything")).rejects.toThrow(/no sources registered/i);
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

    await expect(auth.can("x")).rejects.toThrow(/contract violation/i);
  });

  it("throws when registering a duplicate source name", () => {
    const mizan = createMizan();
    const resolver: SourceResolver = emptySource();
    mizan.registerSource("dup", resolver);

    expect(() => mizan.registerSource("dup", resolver)).toThrow(
      /already registered/i,
    );
  });

  it("throws when a source resolves with null outcome", async () => {
    const mizan = createMizan();
    mizan.registerSource("bad", {
      async resolve() {
        // @ts-expect-error — intentionally null
        return null;
      },
    });
    const auth = mizan.forPrincipal("user-1");

    await expect(auth.can("x")).rejects.toThrow(/contract violation/i);
  });

  it("throws when a source is unavailable", async () => {
    const mizan = createMizan();
    mizan.registerSource("unavail", {
      async resolve() {
        return { status: "unavailable", facts: [] };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    await expect(auth.can("x")).rejects.toThrow(/unavailable/i);
  });

  it("throws when a source returns a fact with null entry", async () => {
    const mizan = createMizan();
    mizan.registerSource("bad", {
      async resolve() {
        return { status: "facts", facts: [null as unknown as AuthorizationFact] };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    await expect(auth.can("x")).rejects.toThrow(/contract violation/i);
  });

  it("throws when a source returns a fact with missing permission", async () => {
    const mizan = createMizan();
    mizan.registerSource("bad", {
      async resolve() {
        return { status: "facts", facts: [{ effect: "grant" } as AuthorizationFact] };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    await expect(auth.can("x")).rejects.toThrow(/contract violation/i);
  });

  it("throws when a source returns a fact with unsupported effect", async () => {
    const mizan = createMizan();
    mizan.registerSource("bad", {
      async resolve() {
        return { status: "facts", facts: [{ permission: "x", effect: "maybe" }] as AuthorizationFact[] };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    await expect(auth.can("x")).rejects.toThrow(/contract violation/i);
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

// ─── Plan registration ────────────────────────────────────────────────────────

describe("registerPlan()", () => {
  it("registers a named plan", () => {
    const mizan = createMizan();
    mizan.registerSource("mem", emptySource());
    mizan.registerPlan("standard", {
      name: "standard",
      strategy: "merge",
      sources: [{ sourceName: "mem", required: true }],
    });
    // No throw = success
  });

  it("throws on duplicate plan name", () => {
    const mizan = createMizan();
    mizan.registerSource("mem", emptySource());
    const plan: SourcePlan = {
      name: "dup",
      strategy: "merge",
      sources: [{ sourceName: "mem", required: true }],
    };
    mizan.registerPlan("dup", plan);
    expect(() => mizan.registerPlan("dup", plan)).toThrow(/already registered/i);
  });
});

// ─── Plan-scoped evaluation ───────────────────────────────────────────────────

describe("Plan-scoped evaluation", () => {
  it("resolves facts from the plan's single source", async () => {
    const mizan = createMizan();
    mizan.registerSource("facts", sourceWith({ permission: "files.read", effect: "grant" }));
    mizan.registerPlan("main", {
      name: "main",
      strategy: "merge",
      sources: [{ sourceName: "facts", required: true }],
    });

    const auth = mizan.forPrincipal("user-1", "main");
    expect(await auth.can("files.read")).toBe(true);
  });

  it("resolves only sources in the plan, ignoring unregistered sources", async () => {
    const mizan = createMizan();
    mizan.registerSource("included", sourceWith({ permission: "files.read", effect: "grant" }));
    // Not registered to any plan, but still in the registry
    mizan.registerSource("unused", sourceWith({ permission: "files.delete", effect: "grant" }));
    mizan.registerPlan("subset", {
      name: "subset",
      strategy: "merge",
      sources: [{ sourceName: "included", required: true }],
    });

    const auth = mizan.forPrincipal("user-1", "subset");
    // "files.read" is in the plan's source
    expect(await auth.can("files.read")).toBe(true);
    // "files.delete" is NOT in the plan's source but IS registered globally
    expect(await auth.can("files.delete")).toBe(false);
  });

  it("deny decision from plan-scoped evaluation matches all-source behavior", async () => {
    const mizan = createMizan();
    mizan.registerSource("src", sourceWith({ permission: "files.read", effect: "deny" }));
    mizan.registerPlan("main", {
      name: "main",
      strategy: "merge",
      sources: [{ sourceName: "src", required: true }],
    });

    const auth = mizan.forPrincipal("user-1", "main");
    expect(await auth.can("files.read")).toBe(false);

    const result = await auth.decide("files.read");
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("matching-denial");
  });

  it("throws when plan references a non-existent required source", async () => {
    const mizan = createMizan();
    // Register a real source so the evaluator passes the "no sources" guard
    mizan.registerSource("real", emptySource());
    // But the plan references a different source that doesn't exist — required
    mizan.registerPlan("broken", {
      name: "broken",
      strategy: "merge",
      sources: [{ sourceName: "nonexistent", required: true }],
    });

    const auth = mizan.forPrincipal("user-1", "broken");
    await expect(auth.can("anything")).rejects.toThrow(/source.*nonexistent.*not found/i);
  });

  it("skips missing optional source instead of throwing", async () => {
    const mizan = createMizan();
    mizan.registerSource("primary", sourceWith({ permission: "files.read", effect: "grant" }));
    // Plan references a missing source as optional
    mizan.registerPlan("with-optional", {
      name: "with-optional",
      strategy: "merge",
      sources: [
        { sourceName: "primary", required: true },
        { sourceName: "missing-optional", required: false },
      ],
    });

    const auth = mizan.forPrincipal("user-1", "with-optional");
    // Should not throw — missing optional source is skipped
    await expect(auth.can("files.read")).resolves.toBe(true);
  });

  it("throws when plan name was never registered", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", emptySource());
    const auth = mizan.forPrincipal("user-1", "unknown-plan");
    await expect(auth.can("x")).rejects.toThrow(/plan.*unknown-plan.*not found/i);
  });
});

// ─── Resolve context ──────────────────────────────────────────────────────────

describe("Resolve context", () => {
  it("passes principalId, now, and optional signal to source resolver", async () => {
    let capturedContext: ResolveContext | null = null;

    const capturingSource: SourceResolver = {
      async resolve(ctx: ResolveContext) {
        capturedContext = ctx;
        return { status: "facts", facts: [], freshness: "fresh" };
      },
    };

    const mizan = createMizan();
    mizan.registerSource("cap", capturingSource);
    const auth = mizan.forPrincipal("user-99");
    await auth.can("files.read");

    expect(capturedContext).not.toBeNull();
    expect(capturedContext!.principalId).toBe("user-99");
    expect(capturedContext!.now).toBeInstanceOf(Date);
    expect(isNaN(capturedContext!.now.getTime())).toBe(false);
    // signal is optional
  });
});

// ─── Custom source replacement ────────────────────────────────────────────────

describe("Custom source replacement", () => {
  it("custom source with same facts produces same decision as memory adapter", async () => {
    const mizan1 = createMizan();
    const memorySource: SourceResolver = {
      async resolve(_ctx: ResolveContext): Promise<SourceOutcome> {
        return {
          status: "facts",
          facts: [{ permission: "files.read", effect: "grant" }],
          freshness: "fresh",
        };
      },
    };
    mizan1.registerSource("mem", memorySource);
    const auth1 = mizan1.forPrincipal("user-1");

    // Custom source providing identical facts
    const mizan2 = createMizan();
    const customSource: SourceResolver = {
      async resolve(_ctx: ResolveContext): Promise<SourceOutcome> {
        return {
          status: "facts",
          facts: [{ permission: "files.read", effect: "grant" }],
          freshness: "fresh",
        };
      },
    };
    mizan2.registerSource("custom", customSource);
    const auth2 = mizan2.forPrincipal("user-1");

    expect(await auth1.can("files.read")).toBe(await auth2.can("files.read"));
    expect(await auth1.can("files.write")).toBe(await auth2.can("files.write"));
  });
});

// ─── Adapter provides facts, core decides ─────────────────────────────────────

describe("Adapter is fact provider, core is decision maker", () => {
  it("adapter returns facts, core evaluates and decides allow", async () => {
    const adapter: SourceResolver = {
      async resolve(_ctx: ResolveContext): Promise<SourceOutcome> {
        return {
          status: "facts" as const,
          facts: [{ permission: "admin.*", effect: "grant" }],
          freshness: "fresh",
        };
      },
    };

    const mizan = createMizan();
    mizan.registerSource("adapter", adapter);
    const auth = mizan.forPrincipal("user-1");

    // Adapter returns facts, core decides based on them
    expect(await auth.can("admin.*")).toBe(true);

    const result = await auth.decide("admin.*");
    expect(result.decision).toBe("allow");
    expect(result.reason).toBeNull();
  });

  it("adapter outcome does not contain a decision field", async () => {
    const adapter: SourceResolver = {
      async resolve(_ctx: ResolveContext): Promise<SourceOutcome> {
        return {
          status: "facts",
          facts: [{ permission: "files.read", effect: "grant" }],
          freshness: "fresh",
        };
      },
    };

    const outcome = await adapter.resolve({
      principalId: "user-1",
      now: new Date(),
    });

    expect("decision" in outcome).toBe(false);
    expect(outcome.status).toBe("facts");
    expect(outcome.facts).toHaveLength(1);
    expect(outcome.facts[0]!.effect).toBe("grant");
  });
});

// ─── No-plan (default all-source) still works ─────────────────────────────────

describe("Default all-source resolution", () => {
  it("forPrincipal without plan name resolves all registered sources", async () => {
    const mizan = createMizan();
    mizan.registerSource("srcA", sourceWith({ permission: "perm.a", effect: "grant" }));
    mizan.registerSource("srcB", sourceWith({ permission: "perm.b", effect: "grant" }));

    const auth = mizan.forPrincipal("user-1");
    expect(await auth.can("perm.a")).toBe(true);
    expect(await auth.can("perm.b")).toBe(true);
  });
});
