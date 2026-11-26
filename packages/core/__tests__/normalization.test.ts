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

  test("keeps assignment and permission schedules conjunctive with scope and half-open validity", () => {
    const startsAt = Date.parse("2024-06-17T14:00:00Z");
    const expiresAt = startsAt + 60_000;
    const { facts } = expandRoles(
      [{ name: "editor", permissions: [{ permission: "files.edit", effect: "grant", schedules: [{ timezone: "America/New_York", weeks: [{ day: "monday", times: [{ start: "10:00", end: "11:00" }] }] }] }] }],
      [{ roleName: "editor", scope: { org: "north" }, startsAt, expiresAt, schedules: [{ timezone: "UTC", weeks: [{ day: "monday", times: [{ start: "09:00", end: "17:00" }] }] }] }],
    );

    expect(facts[0]).toEqual({
      permission: "files.edit", effect: "grant", scope: { org: "north" }, startsAt, expiresAt,
      schedules: [
        { timezone: "UTC", weeks: [{ day: "monday", times: [{ start: "09:00", end: "17:00" }] }], dates: [] },
        { timezone: "America/New_York", weeks: [{ day: "monday", times: [{ start: "10:00", end: "11:00" }] }], dates: [] },
      ],
    });
    const snapshot = { facts, knownActions: ["files.edit"] };
    const decide = (at: number, org = "north") => evaluate({ action: "files.edit", at, scope: { org }, snapshot });
    expect(decide(startsAt).outcome).toBe("allow");
    expect(decide(startsAt - 1).code).toBe("no-applicable-grant");
    expect(decide(expiresAt).code).toBe("no-applicable-grant");
    expect(decide(startsAt, "south").code).toBe("no-applicable-grant");
    expect(decide(Date.parse("2024-06-17T15:00:00Z")).code).toBe("no-applicable-grant");
  });

  test("retains recurring restrictions on role denials and direct facts", () => {
    const day = { timezone: "UTC", dates: [{ date: "2024-06-17", times: [{ start: "14:00", end: "15:00" }] }] };
    const { facts } = expandRoles(
      [{ name: "reviewer", permissions: [{ permission: "reports.read", effect: "grant" }, { permission: "reports.read", effect: "deny", schedules: [day] }] }],
      [{ roleName: "reviewer" }],
      [{ permission: "reports.export", effect: "grant", schedules: [day] }],
    );
    const snapshot = { facts, knownActions: ["reports.read", "reports.export"] };
    const decide = (action: string, at: string) => evaluate({ action, at: Date.parse(at), snapshot });
    expect(decide("reports.read", "2024-06-17T14:30:00Z").code).toBe("explicit-deny");
    expect(decide("reports.read", "2024-06-17T15:00:00Z").outcome).toBe("allow");
    expect(decide("reports.export", "2024-06-17T14:30:00Z").outcome).toBe("allow");
    expect(decide("reports.export", "2024-06-17T15:00:00Z").code).toBe("no-applicable-grant");
  });

  test("validates schedules before suppressing conflicting or empty role facts", () => {
    const malformedSchedules = [{ timezone: "UTC", weeks: [{ day: "monday", times: [{ start: "25:00", end: "26:00" }] }] }];
    expect(() => expandRoles(
      [{ name: "unused", permissions: [{ permission: "files.read", effect: "grant", schedules: malformedSchedules }] }],
      [],
    )).toThrow(AuthorizationFault);
    expect(() => expandRoles(
      [{ name: "role", permissions: [{ permission: "files.read", effect: "grant", scope: { org: "north" }, schedules: malformedSchedules }] }],
      [{ roleName: "role", scope: { org: "south" } }],
    )).toThrow(AuthorizationFault);
    expect(() => expandRoles(
      [{ name: "role", permissions: [{ permission: "files.read", effect: "deny", expiresAt: 10, schedules: malformedSchedules }] }],
      [{ roleName: "role", startsAt: 10 }],
    )).toThrow(AuthorizationFault);
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

  test("copies scopes and schedules before callers mutate input", () => {
    const permissionScope = { project: "one" };
    const assignmentScope = { org: "north" };
    const directScope = { org: "south" };
    const assignmentSchedules = [{ timezone: "UTC", weeks: [{ day: "monday" as const, times: [{ start: "09:00", end: "17:00" }] }] }];
    const permissionSchedules = [{ timezone: "America/New_York", dates: [{ date: "2024-06-17", times: [{ start: "10:00", end: "11:00" }] }] }];
    const directSchedules = [{ timezone: "UTC", dates: [{ date: "2024-06-17", times: [{ start: "14:00", end: "15:00" }] }] }];
    const { facts } = expandRoles(
      [{ name: "role", permissions: [{ permission: "records.read", effect: "grant", scope: permissionScope, schedules: permissionSchedules }] }],
      [{ roleName: "role", scope: assignmentScope, schedules: assignmentSchedules, provenanceId: "assignment" }],
      [{ permission: "records.read", effect: "deny", scope: directScope, startsAt: 0, expiresAt: 0, schedules: directSchedules, provenanceId: "revoke" }],
    );
    permissionScope.project = "other";
    assignmentScope.org = "changed";
    directScope.org = "changed";
    assignmentSchedules[0]!.weeks![0]!.times[0]!.start = "00:00";
    permissionSchedules[0]!.timezone = "UTC";
    directSchedules[0]!.dates[0]!.date = "2024-06-18";
    expect(facts).toEqual([
      { permission: "records.read", effect: "grant", scope: { org: "north", project: "one" }, provenanceId: "assignment", schedules: [
        { timezone: "UTC", weeks: [{ day: "monday", times: [{ start: "09:00", end: "17:00" }] }], dates: [] },
        { timezone: "America/New_York", weeks: [], dates: [{ date: "2024-06-17", times: [{ start: "10:00", end: "11:00" }] }] },
      ] },
      { permission: "records.read", effect: "deny", scope: { org: "south" }, startsAt: 0, expiresAt: 0, provenanceId: "revoke", schedules: [
        { timezone: "UTC", weeks: [], dates: [{ date: "2024-06-17", times: [{ start: "14:00", end: "15:00" }] }] },
      ] },
    ]);
  });

  test.each([
    { schedule: {} }, { schedule: undefined }, { schedules: [{ timezone: "No/Such_Zone", weeks: [] }] }, { kind: "role" }, { effect: "allow" },
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
    { schedule: {} }, { schedule: undefined }, { schedules: [{ timezone: "UTC" }] }, { effect: "grant" }, { scope: null },
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

  test.each(["permission-source", ""])("permission provenance %j takes precedence over assignment provenance", (provenanceId) => {
    const { facts } = expandRoles(
      [{ name: "reader", permissions: [{ permission: "files.read", effect: "grant", provenanceId }] }],
      [{ roleName: "reader", provenanceId: "assignment-source" }],
    );
    expect(facts).toEqual([{ permission: "files.read", effect: "grant", provenanceId }]);
  });

  test("missing roles throw the stable public input fault category", () => {
    let caught: unknown;
    try {
      expandRoles([], [{ roleName: "missing" }]);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(AuthorizationFault);
    expect((caught as AuthorizationFault).code).toBe("invalid-input");
  });

  test("bounds diagnostics when many role facts are omitted", () => {
    const permissions = Array.from({ length: 24 }, (_, index) => ({ permission: `files.${index}`, effect: "grant" as const, scope: { org: "north" } }));
    const result = expandRoles([{ name: "reader", permissions }], [{ roleName: "reader", scope: { org: "south" } }]);

    expect(result.facts).toEqual([]);
    expect(result.diagnostics).toHaveLength(20);
    expect(result.omittedDiagnostics).toBe(4);
  });
});
