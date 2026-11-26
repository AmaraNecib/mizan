import { describe, expect, test } from "bun:test";
import { AuthorizationFault, evaluate } from "../src/direct-evaluation.js";
import { expandRoles } from "../src/normalization.js";

describe("expandRoles", () => {
  test("intersects role permission and assignment scope and validity", () => {
    const result = expandRoles(
      [{ name: "editor", permissions: [{ permission: "files.edit", effect: "grant", scope: { org: "north" }, startsAt: 10, expiresAt: 90 }] }],
      [{ roleName: "editor", scope: { org: "north", team: "red" }, startsAt: 20, expiresAt: 80 }],
    );

    expect(result.facts).toEqual([
      { permission: "files.edit", effect: "grant", scope: { org: "north", team: "red" }, startsAt: 20, expiresAt: 80 },
    ]);
    expect(result.diagnostics).toEqual([]);
  });

  test("preserves intersected restrictions on denials and omits empty intersections", () => {
    const result = expandRoles(
      [{ name: "auditor", permissions: [
        { permission: "records.read", effect: "deny", startsAt: 5, expiresAt: 30 },
        { permission: "records.delete", effect: "grant", scope: { region: "west" } },
        { permission: "records.write", effect: "deny", startsAt: 40 },
      ] }],
      [{ roleName: "auditor", startsAt: 10, expiresAt: 30, scope: { region: "east" } }],
    );

    expect(result.facts).toEqual([{ permission: "records.read", effect: "deny", scope: { region: "east" }, startsAt: 10, expiresAt: 30 }]);
    expect(result.diagnostics).toEqual([
      { code: "scope-conflict", roleName: "auditor", permission: "records.delete" },
      { code: "empty-validity", roleName: "auditor", permission: "records.write" },
    ]);
    expect(evaluate({ action: "records.read", at: 15, scope: { region: "east" }, snapshot: { facts: result.facts, knownActions: ["records.read"] } })).toEqual({ outcome: "deny", code: "explicit-deny" });
  });

  test("appends validated direct facts without mutating caller input", () => {
    const directFacts = [{ permission: "files.read", effect: "deny" as const, scope: { org: "north" } }];
    const before = structuredClone(directFacts);
    const result = expandRoles([], [], directFacts);

    expect(result.facts).toEqual(before);
    expect(directFacts).toEqual(before);
    expect(result.facts).not.toBe(directFacts);
  });

  test("validates unused roles, duplicate definitions, and missing assignment references", () => {
    expect(() => expandRoles([{ name: "unused", permissions: [{ permission: "x.read", effect: "grant", schedule: undefined } as never] }], [])).toThrow(AuthorizationFault);
    expect(() => expandRoles([{ name: "same", permissions: [] }, { name: "same", permissions: [] }], [])).toThrow(/Duplicate role/);
    expect(() => expandRoles([], [{ roleName: "missing" }])).toThrow(/Missing role definition/);
  });

  test("rejects malformed objects and arrays instead of invoking caller behavior", () => {
    const accessor = Object.defineProperty({}, "permission", { get: () => "x.read", enumerable: true });
    expect(() => expandRoles([{ name: "reader", permissions: [accessor as never] }], [])).toThrow(/accessors/);
    expect(() => expandRoles([{ name: "reader", permissions: [{ permission: "x.read", effect: "grant" }] }], [,] as never)).toThrow(/sparse/);
    expect(() => expandRoles([{ name: "reader", permissions: [{ permission: "x.read", effect: "grant" }] }], [{ roleName: "reader", schedule: undefined } as never])).toThrow(/unsupported field/);
    expect(() => expandRoles([{ name: "reader", permissions: [{ permission: "x.read", effect: "grant" }] }], [], [{ permission: "x.read", effect: "grant", [Symbol("extra")]: true } as never])).toThrow(/string-keyed/);
    const emptyWindow = expandRoles([{ name: "reader", permissions: [{ permission: "x.read", effect: "grant", startsAt: 4, expiresAt: 4 }] }], [{ roleName: "reader" }]);
    expect(emptyWindow.facts).toEqual([]);
    expect(emptyWindow.diagnostics).toEqual([{ code: "empty-validity", roleName: "reader", permission: "x.read" }]);
  });

  test("bounds diagnostics when many role facts are omitted", () => {
    const permissions = Array.from({ length: 24 }, (_, index) => ({ permission: `files.${index}`, effect: "grant" as const, scope: { org: "north" } }));
    const result = expandRoles([{ name: "reader", permissions }], [{ roleName: "reader", scope: { org: "south" } }]);

    expect(result.facts).toEqual([]);
    expect(result.diagnostics).toHaveLength(20);
    expect(result.omittedDiagnostics).toBe(4);
  });
});
