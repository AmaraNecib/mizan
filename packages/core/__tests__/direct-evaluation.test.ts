import { describe, expect, it } from "bun:test";
import * as core from "@mizan/core";

describe("@mizan/core direct evaluator", () => {
  it("allows recognized exact grants and denies unknown keys under wildcard grants", () => {
    const snapshot = {
      facts: [{ permission: "*", effect: "grant" as const }],
      knownActions: ["files.read"],
    };
    const input = { action: "files.read", snapshot, at: 1_700_000_000_000 };

    expect(core.evaluate(input)).toEqual({
      outcome: "allow",
      code: "granted",
      recognition: "known",
    });
    expect(core.evaluate({ ...input, action: "files.delete" })).toEqual({
      outcome: "deny",
      code: "unknown-action",
    });
    expect(core.evaluate({
      ...input,
      snapshot: {
        knownActions: ["files.read"],
        facts: [{ permission: "files.read", effect: "grant" }],
      },
    })).toEqual({ outcome: "allow", code: "granted", recognition: "known" });
    expect(core.evaluate({ ...input, snapshot: { knownActions: ["files.read"], facts: [] } })).toEqual({
      outcome: "deny",
      code: "no-applicable-grant",
    });
  });

  it("lets an active matching denial override an exact grant", () => {
    const result = core.evaluate({
      action: "files.read",
      at: 10,
      snapshot: {
        knownActions: ["files.read"],
        facts: [
          { permission: "files.*", effect: "grant" },
          { permission: "files.read", effect: "deny", startsAt: 10, expiresAt: 11 },
        ],
      },
    });

    expect(result).toEqual({ outcome: "deny", code: "explicit-deny" });
  });

  it("applies explicit time and exact-dimension scope", () => {
    const input = {
      action: "files.read",
      at: 10,
      scope: { tenant: "a", project: "p" },
      snapshot: {
        knownActions: ["files.read"],
        facts: [{
          permission: "files.read",
          effect: "grant" as const,
          scope: { tenant: "a" },
          startsAt: 10,
          expiresAt: 11,
        }],
      },
    };

    expect(core.evaluate(input).outcome).toBe("allow");
    expect(core.evaluate({ ...input, at: 11 }).outcome).toBe("deny");
    expect(core.evaluate({ ...input, scope: { tenant: "b" } }).outcome).toBe("deny");
  });

  it("validates the whole snapshot and exposes a typed fault", () => {
    const input = {
      action: "files.read",
      at: 10,
      snapshot: {
        knownActions: ["files.read"],
        facts: [
          { permission: "files.read", effect: "grant" },
          { permission: "unrelated.*", effect: "deny", schedule: {} },
        ],
      },
    };

    try {
      core.evaluate(input as never);
      throw new Error("Expected malformed fact to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(core.AuthorizationFault);
      expect((error as core.AuthorizationFault).code).toBe("invalid-input");
    }
  });

  it("does not widen a non-enumerable scoped grant to global", () => {
    const hiddenScope = Object.defineProperty({}, "tenant", {
      value: "a", enumerable: false,
    });
    expect(core.evaluate({
      action: "files.read", at: 10, scope: { tenant: "b" },
      snapshot: { knownActions: ["files.read"], facts: [
        { permission: "files.read", effect: "grant", scope: hiddenScope },
      ] },
    })).toEqual({ outcome: "deny", code: "no-applicable-grant" });
  });

  it("rejects accessor-backed fact fields rather than rereading changing values", () => {
    let reads = 0;
    const fact = {
      permission: "files.read",
      get effect() { return ++reads === 1 ? "deny" : "grant"; },
    };
    expect(() => core.evaluate({
      action: "files.read", at: 10,
      snapshot: { knownActions: ["files.read"], facts: [fact] },
    } as never)).toThrow(core.AuthorizationFault);
    expect(reads).toBe(0);
  });

  it("matches every dimension even when only one scope property is enumerable", () => {
    const factScope = Object.defineProperty({ project: "p" }, "tenant", {
      value: "a", enumerable: false,
    });
    const input = {
      action: "files.read", at: 10,
      snapshot: { knownActions: ["files.read"], facts: [
        { permission: "files.read", effect: "grant" as const, scope: factScope },
      ] },
    };
    expect(core.evaluate({ ...input, scope: { project: "p", tenant: "b" } }).outcome).toBe("deny");
    expect(core.evaluate({ ...input, scope: { project: "p", tenant: "a" } }).outcome).toBe("allow");
    expect(core.evaluate(input).outcome).toBe("deny");
  });

  it("lets a global denial restrict a scoped grant regardless of fact order", () => {
    const facts: core.EffectiveFact[] = [
      { permission: "files.read", effect: "grant", scope: { tenant: "a" } },
      { permission: "*", effect: "deny" },
    ];
    for (const ordered of [facts, [...facts].reverse()]) {
      expect(core.evaluate({
        action: "files.read", at: 10, scope: { tenant: "a" },
        snapshot: { knownActions: ["files.read"], facts: ordered },
      })).toEqual({ outcome: "deny", code: "explicit-deny" });
    }
  });

  it("keeps namespace matching within descendants and concrete definitions separate", () => {
    const snapshot: core.AuthorizationSnapshot = {
      knownActions: ["files", "files.read", "filesX.read", "files.folder.read", "employees:read"],
      facts: [
        { permission: "files.*", effect: "grant" },
        { permission: "employees:read", effect: "grant" },
        { permission: "runtime.unknown", effect: "grant" },
      ],
    };
    for (const action of ["files.read", "files.folder.read", "employees:read"]) {
      expect(core.evaluate({ action, snapshot, at: 0 }).outcome).toBe("allow");
    }
    for (const action of ["files", "filesX.read"]) {
      expect(core.evaluate({ action, snapshot, at: 0 })).toEqual({ outcome: "deny", code: "no-applicable-grant" });
    }
    expect(core.evaluate({ action: "runtime.unknown", snapshot, at: 0 })).toEqual({ outcome: "deny", code: "unknown-action" });
    expect(core.evaluate({
      action: "runtime.unknown", at: 0,
      snapshot: { ...snapshot, knownActions: [...snapshot.knownActions, "runtime.unknown"] },
    }).outcome).toBe("allow");
  });

  it("uses half-open denial validity and treats zero-length grants as inactive", () => {
    const snapshot: core.AuthorizationSnapshot = {
      knownActions: ["files.read"],
      facts: [
        { permission: "files.read", effect: "grant" },
        { permission: "files.read", effect: "deny", startsAt: 10, expiresAt: 20 },
      ],
    };
    for (const at of [9, 20]) expect(core.evaluate({ action: "files.read", snapshot, at }).outcome).toBe("allow");
    for (const at of [10, 19]) expect(core.evaluate({ action: "files.read", snapshot, at }).code).toBe("explicit-deny");
    expect(core.evaluate({ action: "files.read", at: 10, snapshot: {
      knownActions: ["files.read"],
      facts: [{ permission: "files.read", effect: "grant", startsAt: 10, expiresAt: 10 }],
    } }).code).toBe("no-applicable-grant");
  });

  it.each([
    ["null input", null],
    ["invalid clock", { action: "files.read", at: Number.NaN, snapshot: { facts: [], knownActions: [] } }],
    ["fractional clock", { action: "files.read", at: 1.5, snapshot: { facts: [], knownActions: [] } }],
    ["unsafe clock", { action: "files.read", at: Number.MAX_SAFE_INTEGER + 1, snapshot: { facts: [], knownActions: [] } }],
    ["wildcard query", { action: "files.*", at: 0, snapshot: { facts: [], knownActions: [] } }],
    ["empty segment", { action: "files..read", at: 0, snapshot: { facts: [], knownActions: [] } }],
    ["unknown input field", { action: "files.read", at: 0, policy: {}, snapshot: { facts: [], knownActions: [] } }],
    ["wildcard definition", { action: "files.read", at: 0, snapshot: { facts: [], knownActions: ["*"] } }],
    ["missing facts", { action: "files.read", at: 0, snapshot: { knownActions: ["files.read"] } }],
    ["null fact", { action: "files.read", at: 0, snapshot: { facts: [null], knownActions: ["files.read"] } }],
    ["unsupported effect", { action: "files.read", at: 0, snapshot: { facts: [{ permission: "files.read", effect: "revoke" }], knownActions: ["files.read"] } }],
    ["inverted validity", { action: "files.read", at: 0, snapshot: { facts: [{ permission: "files.read", effect: "deny", startsAt: 20, expiresAt: 10 }], knownActions: ["files.read"] } }],
    ["invalid bound", { action: "files.read", at: 0, snapshot: { facts: [{ permission: "files.read", effect: "deny", expiresAt: Number.NaN }], knownActions: ["files.read"] } }],
    ["null scope", { action: "files.read", at: 0, snapshot: { facts: [{ permission: "files.read", effect: "deny", scope: null }], knownActions: ["files.read"] } }],
    ["empty scope value", { action: "files.read", at: 0, snapshot: { facts: [{ permission: "files.read", effect: "grant", scope: { tenant: "" } }], knownActions: ["files.read"] } }],
    ["nonterminal pattern", { action: "files.read", at: 0, snapshot: { facts: [{ permission: "files.*.read", effect: "grant" }], knownActions: ["files.read"] } }],
  ])("rejects %s with a typed fault", (_name, input) => {
    expect(() => core.evaluate(input as never)).toThrow(core.AuthorizationFault);
  });

  it("accepts null-prototype data records without mutating caller input", () => {
    const scope = Object.assign(Object.create(null) as Record<string, string>, { tenant: "a" });
    const input = Object.freeze({
      action: "files.read", at: 0, scope,
      snapshot: Object.freeze({ knownActions: Object.freeze(["files.read"]), facts: Object.freeze([
        Object.freeze({ permission: "files.read", effect: "grant" as const }),
      ]) }),
    });
    expect(core.evaluate(input).outcome).toBe("allow");
    expect(Object.getPrototypeOf(scope)).toBeNull();
  });

  it("projects denied results without internal reasons or extra provenance", () => {
    const decision = core.evaluate({ action: "files.read", at: 0, snapshot: { facts: [], knownActions: [] } });
    expect(core.isAllowed(decision)).toBe(false);
    expect(core.toPublic({ ...decision, provenance: "internal" } as core.CoreDecision)).toEqual({ allowed: false });
  });

  it("does not dispatch through caller-supplied array methods", () => {
    const facts = [{ permission: "files.read", effect: "deny" as const }];
    Object.defineProperty(facts, "filter", {
      value: () => [{ permission: "files.read", effect: "grant" }],
    });
    expect(core.evaluate({ action: "files.read", at: 0,
      snapshot: { knownActions: ["files.read"], facts },
    })).toEqual({ outcome: "deny", code: "explicit-deny" });
    const knownActions = ["files.read"];
    Object.defineProperty(knownActions, "includes", { value: () => true });
    expect(core.evaluate({ action: "files.delete", at: 0,
      snapshot: { knownActions, facts: [{ permission: "*", effect: "grant" }] },
    })).toEqual({ outcome: "deny", code: "unknown-action" });
  });

  it("does not let a custom iterator hide malformed indexed facts", () => {
    const facts = [{ permission: "files.read", effect: "grant", schedule: {} }];
    Object.defineProperty(facts, Symbol.iterator, { value: function* () {} });
    expect(() => core.evaluate({ action: "files.read", at: 0,
      snapshot: { knownActions: ["files.read"], facts },
    } as never)).toThrow(core.AuthorizationFault);
  });

  it("evaluates copied scope data rather than repeatedly invoking proxy reads", () => {
    let reads = 0;
    const scope = new Proxy({ tenant: "a" }, {
      get(target, key, receiver) {
        if (key === "tenant") return ++reads === 1 ? "a" : "b";
        return Reflect.get(target, key, receiver);
      },
    });
    expect(core.evaluate({ action: "files.read", at: 0, scope: { tenant: "b" },
      snapshot: { knownActions: ["files.read"], facts: [
        { permission: "files.read", effect: "grant", scope },
      ] },
    })).toEqual({ outcome: "deny", code: "no-applicable-grant" });
  });

  it("projects only the public allowed boolean", () => {
    const decision = core.evaluate({
      action: "files.read",
      at: 10,
      snapshot: {
        knownActions: ["files.read"],
        facts: [{ permission: "files.read", effect: "grant" }],
      },
    });

    expect(core.isAllowed(decision)).toBe(true);
    expect(core.toPublic(decision)).toEqual({ allowed: true });
    expect(Object.keys(core.toPublic(decision))).toEqual(["allowed"]);
  });
});
