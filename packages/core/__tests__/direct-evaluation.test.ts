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
