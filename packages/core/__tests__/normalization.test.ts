import { describe, expect, test } from "bun:test";
import { AuthorizationFault, evaluate } from "@mizan/core";
import { expandRoles } from "@mizan/core/normalization";

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

  test("rejects numeric-looking extra properties outside an array's indexed entries", () => {
    const assignments = Object.assign([], { "4294967295": { roleName: "reader", schedule: {} } });
    expect(() => expandRoles([], assignments)).toThrow(AuthorizationFault);
  });

  test.each(["grant", "deny"] as const)("retains %s permission restrictions when the assignment is broader", (effect) => {
    const { facts } = expandRoles(
      [{ name: "reviewer", permissions: [{ permission: "records.*", effect, scope: { project: "one" }, startsAt: 20, expiresAt: 30 }] }],
      [{ roleName: "reviewer", scope: { org: "north" }, startsAt: 10, expiresAt: 50 }],
    );
    expect(facts).toEqual([{ permission: "records.*", effect, scope: { org: "north", project: "one" }, startsAt: 20, expiresAt: 30 }]);
  });

  test.each(["grant", "deny"] as const)("suppresses %s facts for conflicting scopes or touching intervals", (effect) => {
    expect(expandRoles(
      [{ name: "role", permissions: [{ permission: "records.read", effect, scope: { org: "north" } }] }],
      [{ roleName: "role", scope: { org: "south" } }],
    ).facts).toEqual([]);
    expect(expandRoles(
      [{ name: "role", permissions: [{ permission: "records.read", effect, expiresAt: 10 }] }],
      [{ roleName: "role", startsAt: 10 }],
    ).facts).toEqual([]);
  });

  test("role and direct grants remain additive while a temporary revoke restricts only its action and scope", () => {
    const { facts } = expandRoles(
      [{ name: "editor", permissions: [{ permission: "records.edit", effect: "grant", provenanceId: "role-grant" }] }],
      [{ roleName: "editor", scope: { org: "north" }, startsAt: 0, expiresAt: 500 }],
      [
        { permission: "reports.read", effect: "grant" },
        { permission: "records.edit", effect: "grant", scope: { org: "south" } },
        { permission: "records.edit", effect: "deny", scope: { org: "north" }, startsAt: 200, expiresAt: 300 },
      ],
    );
    const snapshot = { facts, knownActions: ["records.edit", "reports.read"] };
    const decide = (at: number, action = "records.edit", org = "north") => evaluate({ at, action, scope: { org }, snapshot });
    expect(decide(-1).code).toBe("no-applicable-grant");
    expect(decide(0).outcome).toBe("allow");
    expect(decide(199).outcome).toBe("allow");
    expect(decide(200).code).toBe("explicit-deny");
    expect(decide(299).code).toBe("explicit-deny");
    expect(decide(300).outcome).toBe("allow");
    expect(decide(500).code).toBe("no-applicable-grant");
    expect(decide(250, "reports.read").outcome).toBe("allow");
    expect(decide(250, "records.edit", "south").outcome).toBe("allow");
  });

  test("copies scopes before callers mutate input and preserves direct empty windows", () => {
    const permissionScope = { project: "one" };
    const assignmentScope = { org: "north" };
    const directScope = { org: "south" };
    const { facts } = expandRoles(
      [{ name: "role", permissions: [{ permission: "records.read", effect: "grant", scope: permissionScope }] }],
      [{ roleName: "role", scope: assignmentScope, provenanceId: "assignment" }],
      [{ permission: "records.read", effect: "deny", scope: directScope, startsAt: 0, expiresAt: 0, provenanceId: "revoke" }],
    );
    permissionScope.project = "other";
    assignmentScope.org = "changed";
    directScope.org = "changed";
    expect(facts).toEqual([
      { permission: "records.read", effect: "grant", scope: { org: "north", project: "one" }, provenanceId: "assignment" },
      { permission: "records.read", effect: "deny", scope: { org: "south" }, startsAt: 0, expiresAt: 0, provenanceId: "revoke" },
    ]);
  });

  test.each([
    { schedule: {} }, { schedule: undefined }, { kind: "role" }, { effect: "allow" },
    { permission: "records.**" }, { permission: "records..read" }, { permission: "records read" },
    { scope: null }, { scope: { org: "" } }, { scope: { "": "north" } },
    { startsAt: NaN }, { startsAt: 0.5 }, { expiresAt: Infinity }, { expiresAt: Number.MAX_SAFE_INTEGER + 1 },
    { startsAt: 20, expiresAt: 10 }, { provenanceId: 1 },
  ])("rejects malformed role and direct facts %j even when unassigned", (fields) => {
    const malformed = { permission: "records.read", effect: "deny", ...fields } as never;
    expect(() => expandRoles([{ name: "unused", permissions: [malformed] }], [])).toThrow(AuthorizationFault);
    expect(() => expandRoles([], [], [malformed])).toThrow(AuthorizationFault);
  });

  test.each([
    { schedule: {} }, { schedule: undefined }, { effect: "grant" }, { scope: null },
    { scope: { org: 42 } }, { startsAt: NaN }, { expiresAt: 1.5 },
    { startsAt: 20, expiresAt: 10 }, { provenanceId: false },
  ])("rejects malformed assignments %j even when role permissions are empty", (fields) => {
    expect(() => expandRoles([{ name: "empty", permissions: [] }], [{ roleName: "empty", ...fields } as never])).toThrow(AuthorizationFault);
  });

  test("validates every collection shape and does not execute accessors", () => {
    for (const malformed of [null, {}, [undefined], [,]]) {
      expect(() => expandRoles(malformed as never, [])).toThrow(AuthorizationFault);
      expect(() => expandRoles([], malformed as never)).toThrow(AuthorizationFault);
      expect(() => expandRoles([], [], malformed as never)).toThrow(AuthorizationFault);
    }
    let reads = 0;
    const badScope = Object.defineProperty({}, "org", { get() { reads += 1; return "north"; } });
    expect(() => expandRoles([], [], [{ permission: "x", effect: "deny", scope: badScope }])).toThrow(AuthorizationFault);
    expect(reads).toBe(0);
    expect(expandRoles([], [])).toEqual({ facts: [], diagnostics: [], omittedDiagnostics: 0 });
  });

  test("bounds diagnostics when many role facts are omitted", () => {
    const permissions = Array.from({ length: 24 }, (_, index) => ({ permission: `files.${index}`, effect: "grant" as const, scope: { org: "north" } }));
    const result = expandRoles([{ name: "reader", permissions }], [{ roleName: "reader", scope: { org: "south" } }]);

    expect(result.facts).toEqual([]);
    expect(result.diagnostics).toHaveLength(20);
    expect(result.omittedDiagnostics).toBe(4);
  });
});
