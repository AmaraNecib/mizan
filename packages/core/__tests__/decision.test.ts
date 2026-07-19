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

  it("throws when a source returns a fact with empty string scope", async () => {
    const mizan = createMizan();
    mizan.registerSource("bad", {
      async resolve() {
        return { status: "facts", facts: [{ permission: "x", effect: "grant", scope: "" }] };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    await expect(auth.can("x")).rejects.toThrow(/contract violation/i);
  });

  it("throws when a source returns a fact with invalid startsAt", async () => {
    const mizan = createMizan();
    mizan.registerSource("bad", {
      async resolve() {
        return { status: "facts", facts: [{ permission: "x", effect: "grant", startsAt: "not-a-date" }] };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    await expect(auth.can("x")).rejects.toThrow(/contract violation/i);
  });

  it("throws when a source returns a fact with invalid expiresAt", async () => {
    const mizan = createMizan();
    mizan.registerSource("bad", {
      async resolve() {
        return { status: "facts", facts: [{ permission: "x", effect: "grant", expiresAt: "bad-date" }] };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    await expect(auth.can("x")).rejects.toThrow(/contract violation/i);
  });

  it("throws when a source returns a fact with JavaScript-parseable but non-ISO startsAt", async () => {
    const mizan = createMizan();
    mizan.registerSource("bad", {
      async resolve() {
        return { status: "facts", facts: [{ permission: "x", effect: "grant", startsAt: "January 1, 2026" }] };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    await expect(auth.can("x")).rejects.toThrow(/contract violation/i);
  });

  it("throws when a source returns a fact with American-format date as startsAt", async () => {
    const mizan = createMizan();
    mizan.registerSource("bad", {
      async resolve() {
        return { status: "facts", facts: [{ permission: "x", effect: "grant", startsAt: "12/25/2024" }] };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    await expect(auth.can("x")).rejects.toThrow(/contract violation/i);
  });

  it("throws when a source returns a fact with logically invalid ISO date (Feb 30)", async () => {
    const mizan = createMizan();
    mizan.registerSource("bad", {
      async resolve() {
        return { status: "facts", facts: [{ permission: "x", effect: "grant", startsAt: "2024-02-30T00:00:00Z" }] };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    await expect(auth.can("x")).rejects.toThrow(/contract violation/i);
  });

  it("accepts valid leap year date (Feb 29, 2024)", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "x", effect: "grant", startsAt: "2024-02-29T00:00:00Z" }));
    const auth = mizan.forPrincipal("user-1");

    // Should not throw — Feb 29, 2024 is a valid leap year date
    await expect(auth.can("x")).resolves.toBe(true);
  });

  it("rejects Feb 29 in non-leap year (2023)", async () => {
    const mizan = createMizan();
    mizan.registerSource("bad", {
      async resolve() {
        return { status: "facts", facts: [{ permission: "x", effect: "grant", startsAt: "2023-02-29T00:00:00Z" }] };
      },
    });
    const auth = mizan.forPrincipal("user-1");

    await expect(auth.can("x")).rejects.toThrow(/contract violation/i);
  });

  it("zero-length interval (startsAt === expiresAt) is never active", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({ permission: "files.read", effect: "grant", startsAt: "2024-06-15T00:00:00Z", expiresAt: "2024-06-15T00:00:00Z" }),
    );
    const auth = mizan.forPrincipal("user-1");

    // At exactly the same instant, the half-open interval [start, end) is empty
    const result = await auth.decide("files.read", { at: new Date("2024-06-15T00:00:00Z") });
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("expired");
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

// ─── Scope matching ────────────────────────────────────────────────────────

describe("Scope matching", () => {
  it("global fact (no scope) matches any requested scope", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "files.read", effect: "grant" }));
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read", { scope: "tenant-a" })).toBe(true);
    expect(await auth.can("files.read", { scope: "tenant-b" })).toBe(true);
  });

  it("scoped fact matches only the corresponding requested scope", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({ permission: "files.read", effect: "grant", scope: "tenant-a" }),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read", { scope: "tenant-a" })).toBe(true);
    expect(await auth.can("files.read", { scope: "tenant-b" })).toBe(false);
  });

  it("scoped fact does not match when scope is omitted in request", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({ permission: "files.read", effect: "grant", scope: "tenant-a" }),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(false);
  });

  it("omitting requested scope means only global facts apply", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        { permission: "files.read", effect: "grant" },
        { permission: "files.write", effect: "grant", scope: "tenant-a" },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(true);
    expect(await auth.can("files.write")).toBe(false);
  });

  it("scoped deny overrides scoped grant within same scope", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        { permission: "files.delete", effect: "grant", scope: "tenant-a" },
        { permission: "files.delete", effect: "deny", scope: "tenant-a" },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.delete", { scope: "tenant-a" })).toBe(false);
  });

  it("global (unscoped) denial overrides scoped grant", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        { permission: "files.read", effect: "grant", scope: "tenant-a" },
        { permission: "files.read", effect: "deny" },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    // Global denial matches any scope, overriding the scoped grant
    expect(await auth.can("files.read", { scope: "tenant-a" })).toBe(false);
    expect(await auth.can("files.read", { scope: "tenant-b" })).toBe(false);
  });

  it("deny in one scope does not affect another scope", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        { permission: "files.read", effect: "grant", scope: "tenant-a" },
        { permission: "files.read", effect: "deny", scope: "tenant-b" },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read", { scope: "tenant-a" })).toBe(true);
    expect(await auth.can("files.read", { scope: "tenant-b" })).toBe(false);
  });

  it("decide returns out-of-scope reason when scoped fact doesn't match", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({ permission: "files.read", effect: "grant", scope: "tenant-a" }),
    );
    const auth = mizan.forPrincipal("user-1");

    const result = await auth.decide("files.read", { scope: "tenant-b" });
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("out-of-scope");
  });
});

// ─── Temporal matching ─────────────────────────────────────────────────────

describe("Temporal matching", () => {
  it("fact with no startsAt or expiresAt is always active", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "files.read", effect: "grant" }));
    const auth = mizan.forPrincipal("user-1");

    const past = new Date("2020-01-01T00:00:00Z");
    const future = new Date("2099-01-01T00:00:00Z");
    expect(await auth.can("files.read", { at: past })).toBe(true);
    expect(await auth.can("files.read", { at: future })).toBe(true);
  });

  it("fact with startsAt in the past is active", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({ permission: "files.read", effect: "grant", startsAt: "2024-01-01T00:00:00Z" }),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read", { at: new Date("2024-06-15T00:00:00Z") })).toBe(true);
  });

  it("fact with startsAt in the future is not-yet-active", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({ permission: "files.read", effect: "grant", startsAt: "2025-01-01T00:00:00Z" }),
    );
    const auth = mizan.forPrincipal("user-1");

    const result = await auth.decide("files.read", { at: new Date("2024-06-15T00:00:00Z") });
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("not-yet-active");
  });

  it("fact with expiresAt in the past is expired", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({ permission: "files.read", effect: "grant", expiresAt: "2024-01-01T00:00:00Z" }),
    );
    const auth = mizan.forPrincipal("user-1");

    const result = await auth.decide("files.read", { at: new Date("2024-06-15T00:00:00Z") });
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("expired");
  });

  it("half-open interval: startsAt is inclusive, expiresAt is exclusive", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({ permission: "files.read", effect: "grant", startsAt: "2024-01-01T00:00:00Z", expiresAt: "2024-12-31T23:59:59Z" }),
    );
    const auth = mizan.forPrincipal("user-1");

    // Exactly at startsAt → active (inclusive)
    expect(await auth.can("files.read", { at: new Date("2024-01-01T00:00:00Z") })).toBe(true);
    // Exactly at expiresAt → inactive (exclusive)
    expect(await auth.can("files.read", { at: new Date("2024-12-31T23:59:59Z") })).toBe(false);
    // One ms before expiresAt → active
    expect(await auth.can("files.read", { at: new Date("2024-12-31T23:59:58Z") })).toBe(true);
  });

  it("fact with both startsAt and expiresAt within active window", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({ permission: "files.read", effect: "grant", startsAt: "2024-01-01T00:00:00Z", expiresAt: "2024-12-31T23:59:59Z" }),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read", { at: new Date("2024-06-15T12:00:00Z") })).toBe(true);
  });

  it("expired denial does not deny (treated as inactive)", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        { permission: "files.read", effect: "grant" },
        { permission: "files.read", effect: "deny", expiresAt: "2024-01-01T00:00:00Z" },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    // Denial is expired, grant is still active → allow
    expect(await auth.can("files.read", { at: new Date("2024-06-15T00:00:00Z") })).toBe(true);
  });

  it("not-yet-active denial does not deny (treated as inactive)", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        { permission: "files.read", effect: "grant" },
        { permission: "files.read", effect: "deny", startsAt: "2025-01-01T00:00:00Z" },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    // Denial is not yet active, grant is still active → allow
    expect(await auth.can("files.read", { at: new Date("2024-06-15T00:00:00Z") })).toBe(true);
  });

  it("expired grant with no active alternative → deny expired", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({ permission: "files.read", effect: "grant", expiresAt: "2024-01-01T00:00:00Z" }),
    );
    const auth = mizan.forPrincipal("user-1");

    const result = await auth.decide("files.read", { at: new Date("2024-06-15T00:00:00Z") });
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("expired");
  });
});

// ─── Schedule matching ─────────────────────────────────────────────────────

describe("Schedule matching", () => {
  it("fact with no schedule is always active (no schedule constraint)", async () => {
    const mizan = createMizan();
    mizan.registerSource("mem", sourceWith({ permission: "files.read", effect: "grant" }));
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read")).toBe(true);
  });

  it("weekly window matches during window hours", async () => {
    const mizan = createMizan();
    // Wednesday 2024-06-19 at 14:00 UTC is within 09:00-17:00 UTC on Wednesday
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "UTC",
          weeks: [{ day: "wednesday", times: [{ start: "09:00", end: "17:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read", { at: new Date("2024-06-19T14:00:00Z") })).toBe(true);
  });

  it("weekly window does not match outside window hours", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "UTC",
          weeks: [{ day: "wednesday", times: [{ start: "09:00", end: "17:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // At 18:00 UTC on Wednesday - outside 09:00-17:00
    const result = await auth.decide("files.read", { at: new Date("2024-06-19T18:00:00Z") });
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("outside-schedule");
  });

  it("weekly window does not match on a different day", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "UTC",
          weeks: [{ day: "monday", times: [{ start: "09:00", end: "17:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // Wednesday 2024-06-19 at 14:00 UTC - not Monday
    const result = await auth.decide("files.read", { at: new Date("2024-06-19T14:00:00Z") });
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("outside-schedule");
  });

  it("multiple time windows per day (OR logic)", async () => {
    const mizan = createMizan();
    // Wednesday, two windows: 09:00-12:00 OR 14:00-17:00
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "UTC",
          weeks: [{ day: "wednesday", times: [{ start: "09:00", end: "12:00" }, { start: "14:00", end: "17:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // 10:00 is in first window
    expect(await auth.can("files.read", { at: new Date("2024-06-19T10:00:00Z") })).toBe(true);
    // 15:00 is in second window
    expect(await auth.can("files.read", { at: new Date("2024-06-19T15:00:00Z") })).toBe(true);
    // 13:00 is between windows — outside both
    expect(await auth.can("files.read", { at: new Date("2024-06-19T13:00:00Z") })).toBe(false);
  });

  it("decide returns outside-schedule reason for schedule mismatch", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "UTC",
          weeks: [{ day: "wednesday", times: [{ start: "09:00", end: "12:00" }, { start: "14:00", end: "17:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    const result = await auth.decide("files.read", { at: new Date("2024-06-19T13:00:00Z") });
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("outside-schedule");
  });

  it("date-specific window crosses midnight into next day (overnight)", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "UTC",
          dates: [{ date: "2024-12-31", times: [{ start: "22:00", end: "02:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // Dec 31 at 23:00 UTC — within window
    expect(await auth.can("files.read", { at: new Date("2024-12-31T23:00:00Z") })).toBe(true);
    // Jan 1 at 01:00 UTC — next day, still within overnight window
    expect(await auth.can("files.read", { at: new Date("2025-01-01T01:00:00Z") })).toBe(true);
    // Jan 1 at 03:00 UTC — outside window
    expect(await auth.can("files.read", { at: new Date("2025-01-01T03:00:00Z") })).toBe(false);
  });

  it("fractional timezone offset (Asia/Kolkata UTC+5:30) works", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "Asia/Kolkata",
          weeks: [{ day: "wednesday", times: [{ start: "09:00", end: "17:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // 2024-06-19 03:30 UTC = 09:00 IST — at window start (inclusive)
    expect(await auth.can("files.read", { at: new Date("2024-06-19T03:30:00Z") })).toBe(true);
    // 2024-06-19 04:00 UTC = 09:30 IST — within window
    expect(await auth.can("files.read", { at: new Date("2024-06-19T04:00:00Z") })).toBe(true);
    // 2024-06-19 11:29 UTC = 16:59 IST — within window
    expect(await auth.can("files.read", { at: new Date("2024-06-19T11:29:00Z") })).toBe(true);
    // 2024-06-19 11:31 UTC = 17:01 IST — after window end (exclusive)
    expect(await auth.can("files.read", { at: new Date("2024-06-19T11:31:00Z") })).toBe(false);
  });

  it("leap year date window (Feb 29) works", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "UTC",
          dates: [{ date: "2024-02-29", times: [{ start: "09:00", end: "17:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // Leap day, during window
    expect(await auth.can("files.read", { at: new Date("2024-02-29T12:00:00Z") })).toBe(true);
    // Leap day, outside window
    expect(await auth.can("files.read", { at: new Date("2024-02-29T20:00:00Z") })).toBe(false);
    // Next day (March 1) — no longer active
    expect(await auth.can("files.read", { at: new Date("2024-03-01T12:00:00Z") })).toBe(false);
  });

  it("date-specific window on matching date", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "UTC",
          dates: [{ date: "2024-12-25", times: [{ start: "09:00", end: "17:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    expect(await auth.can("files.read", { at: new Date("2024-12-25T10:00:00Z") })).toBe(true);
    expect(await auth.can("files.read", { at: new Date("2024-12-26T10:00:00Z") })).toBe(false);
  });

  it("overnight window (start > end) works correctly", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "UTC",
          weeks: [{ day: "wednesday", times: [{ start: "22:00", end: "02:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // Wednesday 23:00 UTC — within window (22:00 Wed -> 02:00 Thu)
    expect(await auth.can("files.read", { at: new Date("2024-06-19T23:00:00Z") })).toBe(true);
    // Thursday 01:00 UTC — still within window (Wednesday overnight)
    expect(await auth.can("files.read", { at: new Date("2024-06-20T01:00:00Z") })).toBe(true);
    // Thursday 03:00 UTC — outside window
    expect(await auth.can("files.read", { at: new Date("2024-06-20T03:00:00Z") })).toBe(false);
    // Wednesday 21:00 UTC — before window opens
    expect(await auth.can("files.read", { at: new Date("2024-06-19T21:00:00Z") })).toBe(false);
    // Wednesday 01:00 UTC — early morning of listed day, should NOT match
    // (the window is 22:00 Wed → 02:00 Thu, so Wed 01:00 is before 22:00 Wed)
    expect(await auth.can("files.read", { at: new Date("2024-06-19T01:00:00Z") })).toBe(false);
  });

  it("overnight window early morning of listed day denies (not inside window yet)", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "UTC",
          weeks: [{ day: "wednesday", times: [{ start: "22:00", end: "02:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // Wednesday 01:00 — early morning BEFORE the 22:00-02:00 overnight window opens
    const result = await auth.decide("files.read", { at: new Date("2024-06-19T01:00:00Z") });
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("outside-schedule");
  });

  it("overnight window at midnight of listed day is within evening portion", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "UTC",
          weeks: [{ day: "wednesday", times: [{ start: "22:00", end: "02:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // Wednesday 23:30 — evening portion of overnight window
    expect(await auth.can("files.read", { at: new Date("2024-06-19T23:30:00Z") })).toBe(true);
  });

  it("timezone conversion: local time zone affects matching", async () => {
    const mizan = createMizan();
    // Window is 09:00-17:00 in America/New_York (UTC-4 in June)
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "America/New_York",
          weeks: [{ day: "wednesday", times: [{ start: "09:00", end: "17:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // 2024-06-19 12:00 UTC = 08:00 ET (EDT, UTC-4) → before 09:00 ET
    expect(await auth.can("files.read", { at: new Date("2024-06-19T12:00:00Z") })).toBe(false);
    // 2024-06-19 14:00 UTC = 10:00 ET → within 09:00-17:00 ET
    expect(await auth.can("files.read", { at: new Date("2024-06-19T14:00:00Z") })).toBe(true);
    // 2024-06-19 22:00 UTC = 18:00 ET → after 17:00 ET
    expect(await auth.can("files.read", { at: new Date("2024-06-19T22:00:00Z") })).toBe(false);
  });

  it("fact must satisfy both temporal window AND schedule", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        startsAt: "2024-06-01T00:00:00Z",
        expiresAt: "2024-06-30T23:59:59Z",
        schedule: {
          timezone: "UTC",
          weeks: [{ day: "monday", times: [{ start: "09:00", end: "17:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // Monday 2024-06-17 14:00 UTC — within temporal window AND within schedule
    expect(await auth.can("files.read", { at: new Date("2024-06-17T14:00:00Z") })).toBe(true);
    // Wednesday 2024-06-19 14:00 UTC — within temporal window BUT Wednesday, not Monday
    const scheduleResult = await auth.decide("files.read", { at: new Date("2024-06-19T14:00:00Z") });
    expect(scheduleResult.decision).toBe("deny");
    expect(scheduleResult.reason).toBe("outside-schedule");
    // Monday 2024-05-20 14:00 UTC — within schedule (Monday) BUT outside temporal window (before June)
    const temporalResult = await auth.decide("files.read", { at: new Date("2024-05-20T14:00:00Z") });
    expect(temporalResult.decision).toBe("deny");
    expect(temporalResult.reason).toBe("not-yet-active");
  });

  it("empty schedule (no weeks, no dates arrays) means no active time", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "UTC",
          weeks: [],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    const result = await auth.decide("files.read", { at: new Date("2024-06-19T14:00:00Z") });
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("outside-schedule");
  });

  it("outside-schedule takes priority over not-yet-active when both exist", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith(
        {
          permission: "files.read",
          effect: "grant",
          schedule: {
            timezone: "UTC",
            weeks: [{ day: "monday", times: [{ start: "09:00", end: "17:00" }] }],
          },
        },
        {
          permission: "files.read",
          effect: "grant",
          startsAt: "2025-01-01T00:00:00Z",
        },
      ),
    );
    const auth = mizan.forPrincipal("user-1");

    // Wednesday outside schedule + also not yet active — schedule priority wins
    const result = await auth.decide("files.read", { at: new Date("2024-06-19T14:00:00Z") });
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("outside-schedule");
  });

  it("DST spring-forward: overnight window spanning transition (known limitation)", async () => {
    const mizan = createMizan();
    // Overnight window 22:00-02:00 on Sunday in America/New_York
    // Spring-forward 2024-03-10: clocks jump from 02:00 to 03:00 at 02:00 EST
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "America/New_York",
          weeks: [{ day: "sunday", times: [{ start: "22:00", end: "02:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // Sunday 2024-03-10 22:00 EDT (02:00 UTC Mar 11) — well after spring-forward, normal evening
    // 2024-03-11 02:00 UTC = 2024-03-10 22:00 EDT — within evening portion
    expect(await auth.can("files.read", { at: new Date("2024-03-11T02:00:00Z") })).toBe(true);
    // This test documents current behavior. See issue #45 for DST correctness.
  });

  it("DST fall-back: overnight window spanning transition (known limitation)", async () => {
    const mizan = createMizan();
    // Overnight window 22:00-02:00 on Sunday in America/New_York
    // Fall-back 2024-11-03: clocks fall back from 02:00 EDT to 01:00 EST at 02:00 EDT
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        schedule: {
          timezone: "America/New_York",
          weeks: [{ day: "sunday", times: [{ start: "22:00", end: "02:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // Sunday 2024-11-03 22:00 EST (03:00 UTC Nov 4) — evening portion
    expect(await auth.can("files.read", { at: new Date("2024-11-04T03:00:00Z") })).toBe(true);
    // This test documents current behavior. See issue #45 for DST correctness.
  });

  it("scope, temporal, and schedule all combined (triple-dimension)", async () => {
    const mizan = createMizan();
    mizan.registerSource(
      "mem",
      sourceWith({
        permission: "files.read",
        effect: "grant",
        scope: "tenant-a",
        startsAt: "2024-06-01T00:00:00Z",
        expiresAt: "2024-06-30T23:59:59Z",
        schedule: {
          timezone: "UTC",
          weeks: [{ day: "monday", times: [{ start: "09:00", end: "17:00" }] }],
        },
      }),
    );
    const auth = mizan.forPrincipal("user-1");

    // All three match: correct scope, within temporal window, Monday during hours
    expect(await auth.can("files.read", { scope: "tenant-a", at: new Date("2024-06-17T14:00:00Z") })).toBe(true);
    // Scope mismatch
    expect(await auth.can("files.read", { scope: "tenant-b", at: new Date("2024-06-17T14:00:00Z") })).toBe(false);
    // Temporal mismatch (before startsAt)
    expect(await auth.can("files.read", { scope: "tenant-a", at: new Date("2024-05-20T14:00:00Z") })).toBe(false);
    // Schedule mismatch (Wednesday, not Monday)
    expect(await auth.can("files.read", { scope: "tenant-a", at: new Date("2024-06-19T14:00:00Z") })).toBe(false);
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
