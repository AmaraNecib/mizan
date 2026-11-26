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

  it("applies recurring schedules as OR windows within each schedule and AND across schedules", () => {
    const fact: core.EffectiveFact = {
      permission: "files.read", effect: "grant",
      schedules: [
        { timezone: "UTC", weeks: [{ day: "monday", times: [
          { start: "09:00", end: "10:00" }, { start: "11:00", end: "12:00" },
        ] }] },
        { timezone: "UTC", dates: [{ date: "2024-01-01", times: [{ start: "09:30", end: "11:30" }] }] },
      ],
    };
    const evaluateAt = (at: number) => core.evaluate({ action: "files.read", at,
      snapshot: { knownActions: ["files.read"], facts: [fact] },
    }).outcome;
    expect(evaluateAt(Date.UTC(2024, 0, 1, 9, 30))).toBe("allow");
    expect(evaluateAt(Date.UTC(2024, 0, 1, 10, 30))).toBe("deny");
    expect(evaluateAt(Date.UTC(2024, 0, 1, 11, 30))).toBe("deny");
    expect(evaluateAt(Date.UTC(2024, 0, 2, 9, 30))).toBe("deny");
  });

  it("treats empty conjunction as unrestricted and an empty schedule as inactive", () => {
    const evaluateFact = (schedules: unknown) => core.evaluate({ action: "files.read", at: 0,
      snapshot: { knownActions: ["files.read"], facts: [{ permission: "files.read", effect: "grant", schedules }] },
    });
    expect(evaluateFact([]).outcome).toBe("allow");
    expect(evaluateFact([{ timezone: "UTC", weeks: [] }]).code).toBe("no-applicable-grant");
  });

  it("treats equal endpoints as empty for weekly and date grants and denials", () => {
    const schedules: readonly core.ActivitySchedule[] = [
      { timezone: "UTC", weeks: [{ day: "monday", times: [{ start: "09:00", end: "09:00" }] }] },
      { timezone: "UTC", dates: [{ date: "2024-01-01", times: [{ start: "09:00", end: "09:00" }] }] },
    ];
    for (const schedule of schedules) for (const effect of ["grant", "deny"] as const) {
      const facts: core.EffectiveFact[] = [{ permission: "files.read", effect, schedules: [schedule] }];
      if (effect === "deny") facts.push({ permission: "files.read", effect: "grant" });
      for (const instant of ["2024-01-01T08:59:59.999Z", "2024-01-01T09:00:00Z", "2024-01-01T09:00:00.001Z"]) {
        expect(core.evaluate({ action: "files.read", at: Date.parse(instant), snapshot: { knownActions: ["files.read"], facts } }).code)
          .toBe(effect === "grant" ? "no-applicable-grant" : "granted");
      }
    }
  });

  it("anchors dated overnight windows across the year boundary only to the adjacent date", () => {
    const snapshot: core.AuthorizationSnapshot = { knownActions: ["files.read"], facts: [{ permission: "files.read", effect: "grant", schedules: [{ timezone: "UTC", dates: [{ date: "2024-12-31", times: [{ start: "22:00", end: "02:00" }] }] }] }] };
    for (const [instant, outcome] of [
      ["2024-12-31T01:00:00Z", "deny"], ["2024-12-31T22:00:00Z", "allow"],
      ["2025-01-01T01:59:59.999Z", "allow"], ["2025-01-01T02:00:00Z", "deny"],
      ["2025-01-02T01:00:00Z", "deny"],
    ] as const) expect(core.evaluate({ action: "files.read", at: Date.parse(instant), snapshot }).outcome).toBe(outcome);
  });

  it("rejects sparse nested times and accessors without invoking caller code", () => {
    const sparseTimes = new Array(1);
    let reads = 0;
    const accessorWeek = Object.defineProperty({ day: "monday" }, "times", { get() { reads += 1; return []; } });
    for (const week of [{ day: "monday", times: sparseTimes }, accessorWeek]) {
      expect(() => core.evaluate({ action: "unknown.action", at: 0, snapshot: { knownActions: [], facts: [{ permission: "other.read", effect: "deny", schedules: [{ timezone: "UTC", weeks: [week] }] }] } } as never)).toThrow(core.AuthorizationFault);
    }
    expect(reads).toBe(0);
  });

  it("matches weekly and dated overnight windows on the immediately following local date", () => {
    const evaluateFact = (schedule: unknown, at: number) => core.evaluate({ action: "files.read", at,
      snapshot: { knownActions: ["files.read"], facts: [{ permission: "files.read", effect: "grant", schedules: [schedule] }] },
    }).outcome;
    const weekly = { timezone: "UTC", weeks: [{ day: "sunday", times: [{ start: "22:00", end: "06:00" }] }] };
    expect(evaluateFact(weekly, Date.UTC(2024, 0, 8, 5, 59))).toBe("allow");
    expect(evaluateFact(weekly, Date.UTC(2024, 0, 8, 6))).toBe("deny");
    const dated = { timezone: "UTC", dates: [{ date: "2024-02-29", times: [{ start: "22:00", end: "06:00" }] }] };
    expect(evaluateFact(dated, Date.UTC(2024, 2, 1, 5))).toBe("allow");
    expect(evaluateFact(dated, Date.UTC(2024, 2, 2, 5))).toBe("deny");
  });

  it("uses local wall-clock labels for timezone conversion and DST folds and gaps", () => {
    const evaluateAt = (timezone: string, start: string, end: string, at: number) => core.evaluate({ action: "files.read", at,
      snapshot: { knownActions: ["files.read"], facts: [{ permission: "files.read", effect: "grant", schedules: [{ timezone,
        dates: [{ date: "2024-03-10", times: [{ start, end }] }, { date: "2024-11-03", times: [{ start, end }] }] }] }] },
    }).outcome;
    expect(evaluateAt("America/New_York", "02:00", "03:00", Date.UTC(2024, 2, 10, 7, 30))).toBe("deny");
    expect(evaluateAt("America/New_York", "01:00", "02:00", Date.UTC(2024, 10, 3, 5, 30))).toBe("allow");
    expect(evaluateAt("America/New_York", "01:00", "02:00", Date.UTC(2024, 10, 3, 6, 30))).toBe("allow");
    expect(core.evaluate({ action: "files.read", at: Date.UTC(2024, 2, 31, 0, 30), snapshot: {
      knownActions: ["files.read"], facts: [{ permission: "files.read", effect: "grant", schedules: [{ timezone: "Europe/Berlin",
        dates: [{ date: "2024-03-31", times: [{ start: "01:00", end: "03:00" }] }] }] }],
    } }).outcome).toBe("allow");
    for (const at of [Date.UTC(2024, 9, 27, 0, 30), Date.UTC(2024, 9, 27, 1, 30)]) {
      expect(core.evaluate({ action: "files.read", at, snapshot: {
        knownActions: ["files.read"], facts: [{ permission: "files.read", effect: "grant", schedules: [{ timezone: "Europe/Berlin",
          dates: [{ date: "2024-10-27", times: [{ start: "02:00", end: "03:00" }] }] }] }],
      } }).outcome).toBe("allow");
    }
  });

  it("validates every schedule before recognition, permission, scope, or time filtering", () => {
    for (const fact of [
      { permission: "other.read", effect: "grant", schedules: [{ timezone: "No/Such_Zone", weeks: [] }] },
      { permission: "files.read", effect: "deny", scope: { tenant: "other" }, schedules: [{ timezone: "UTC", dates: [{ date: "2024-02-30", times: [] }] }] },
      { permission: "files.read", effect: "grant", startsAt: 100, schedules: [{ timezone: "UTC", weeks: [{ day: "monday", times: [{ start: "24:00", end: "25:00" }] }] }] },
    ]) expect(() => core.evaluate({ action: "unknown.action", at: 0,
      snapshot: { knownActions: [], facts: [fact] },
    } as never)).toThrow(core.AuthorizationFault);
  });

  it("intersects recurring activity with scope and absolute validity, while active denials still win", () => {
    const facts = [
      { permission: "files.read", effect: "grant" as const, scope: { tenant: "a" }, startsAt: 10, expiresAt: 20,
        schedules: [{ timezone: "UTC", dates: [{ date: "1970-01-01", times: [{ start: "00:00", end: "01:00" }] }] }] },
      { permission: "files.read", effect: "deny" as const, schedules: [{ timezone: "UTC", weeks: [{ day: "thursday", times: [{ start: "00:00", end: "01:00" }] }] }] },
    ];
    const input = { action: "files.read", at: 10, scope: { tenant: "a" }, snapshot: { knownActions: ["files.read"], facts } };
    expect(core.evaluate(input)).toEqual({ outcome: "deny", code: "explicit-deny" });
    expect(core.evaluate({ ...input, at: 20, snapshot: { ...input.snapshot, facts: [facts[0]!] } }).code).toBe("no-applicable-grant");
    expect(core.evaluate({ ...input, scope: { tenant: "b" }, snapshot: { ...input.snapshot, facts: [facts[0]!] } }).code).toBe("no-applicable-grant");
  });

  it.each([
    ["fixed offset timezone", [{ timezone: "+02:00", weeks: [] }]],
    ["missing calendar windows", [{ timezone: "UTC" }]],
    ["extra schedule field", [{ timezone: "UTC", weeks: [], interval: "daily" }]],
    ["invalid date", [{ timezone: "UTC", dates: [{ date: "2024-02-30", times: [] }] }]],
    ["non-data schedule", [new Date()]],
    ["unsupported singular field", undefined],
  ])("rejects malformed schedule shape: %s", (_label, schedules) => {
    const fact = { permission: "files.read", effect: "grant", ...(schedules === undefined ? { schedule: {} } : { schedules }) };
    expect(() => core.evaluate({ action: "files.read", at: 0,
      snapshot: { knownActions: ["files.read"], facts: [fact] },
    } as never)).toThrow(core.AuthorizationFault);
  });

  it("preserves the gallery UTC weekday boundaries at millisecond precision", () => {
    const fact: core.EffectiveFact = { permission: "cars.delete", effect: "grant", schedules: [{ timezone: "UTC",
      weeks: (["monday", "tuesday", "wednesday", "thursday", "friday"] as const).map((day) => ({
        day, times: [{ start: "09:00", end: "17:00" }],
      })),
    }] };
    for (const [instant, expected] of [
      ["2024-01-01T08:59:59.999Z", "deny"], ["2024-01-01T09:00:00.000Z", "allow"],
      ["2024-01-01T16:59:59.999Z", "allow"], ["2024-01-01T17:00:00.000Z", "deny"],
      ["2024-01-06T12:00:00.000Z", "deny"],
    ] as const) expect(core.evaluate({ action: "cars.delete", at: Date.parse(instant),
      snapshot: { knownActions: ["cars.delete"], facts: [fact] },
    }).outcome).toBe(expected);
  });

  it("anchors overnight dates to adjacent local dates across short and long DST days", () => {
    for (const [date, start, end, instant, expected] of [
      ["2024-03-10", "22:00", "02:00", "2024-03-11T04:30:00Z", "allow"],
      ["2024-03-09", "22:00", "02:00", "2024-03-11T04:30:00Z", "deny"],
      ["2024-11-02", "23:50", "23:45", "2024-11-04T04:30:00Z", "allow"],
      ["2024-11-03", "23:50", "23:45", "2024-11-04T04:30:00Z", "deny"],
    ] as const) expect(core.evaluate({ action: "files.read", at: Date.parse(instant), snapshot: {
      knownActions: ["files.read"], facts: [{ permission: "files.read", effect: "grant", schedules: [{
        timezone: "America/New_York", dates: [{ date, times: [{ start, end }] }],
      }] }],
    } }).outcome).toBe(expected);
  });

  it("never aliases a BCE instant to a CE date-specific grant", () => {
    expect(core.evaluate({ action: "files.read", at: Date.parse("0000-01-01T12:00:00Z"), snapshot: {
      knownActions: ["files.read"], facts: [{ permission: "files.read", effect: "grant", schedules: [{ timezone: "UTC",
        dates: [{ date: "0001-01-01", times: [{ start: "09:00", end: "17:00" }] }],
      }] }],
    } }).code).toBe("no-applicable-grant");
  });

  it("keeps CE denials and overnight windows distinct from BCE calendar dates", () => {
    const denial: core.EffectiveFact = { permission: "files.read", effect: "deny", schedules: [{ timezone: "UTC", dates: [{ date: "0001-01-01", times: [{ start: "00:00", end: "01:00" }] }] }] };
    const snapshot: core.AuthorizationSnapshot = { knownActions: ["files.read"], facts: [{ permission: "files.read", effect: "grant" }, denial] };
    expect(core.evaluate({ action: "files.read", at: Date.parse("0000-01-01T00:30:00Z"), snapshot }).code).toBe("granted");
    expect(core.evaluate({ action: "files.read", at: Date.parse("0001-01-01T00:30:00Z"), snapshot }).code).toBe("explicit-deny");
    const overnight: core.AuthorizationSnapshot = { knownActions: ["files.read"], facts: [{ permission: "files.read", effect: "grant", schedules: [{ timezone: "UTC", dates: [{ date: "0001-01-01", times: [{ start: "22:00", end: "02:00" }] }] }] }] };
    for (const [instant, outcome] of [
      ["0000-12-31T23:00:00Z", "deny"], ["0001-01-01T01:00:00Z", "deny"],
      ["0001-01-01T22:00:00Z", "allow"], ["0001-01-02T01:00:00Z", "allow"],
      ["0001-01-02T02:00:00Z", "deny"],
    ] as const) expect(core.evaluate({ action: "files.read", at: Date.parse(instant), snapshot: overnight }).outcome).toBe(outcome);
  });

  it.each([Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER])("rejects scheduled instant %s outside Date range as AuthorizationFault", (at) => {
    expect(() => core.evaluate({ action: "files.read", at, snapshot: {
      knownActions: ["files.read"], facts: [{ permission: "files.read", effect: "grant", schedules: [{ timezone: "UTC", weeks: [] }] }],
    } })).toThrow(core.AuthorizationFault);
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

  it("reports an explicit denial before unknown-action recognition", () => {
    expect(core.evaluate({ action: "files.delete", at: 0, snapshot: {
      knownActions: ["files.read"], facts: [{ permission: "*", effect: "deny" }],
    } })).toEqual({ outcome: "deny", code: "explicit-deny" });
  });

  it("treats an empty fact scope as global for a scoped request", () => {
    expect(core.evaluate({ action: "files.read", at: 0, scope: { tenant: "a" },
      snapshot: { knownActions: ["files.read"], facts: [
        { permission: "files.read", effect: "grant", scope: {} },
      ] },
    })).toEqual({ outcome: "allow", code: "granted", recognition: "known" });
  });

  it("ignores an out-of-scope denial while applying a global grant", () => {
    expect(core.evaluate({ action: "files.read", at: 0, scope: { tenant: "a" },
      snapshot: { knownActions: ["files.read"], facts: [
        { permission: "files.read", effect: "grant" },
        { permission: "files.read", effect: "deny", scope: { tenant: "b" } },
      ] },
    })).toEqual({ outcome: "allow", code: "granted", recognition: "known" });
  });

  it.each([Number.MIN_SAFE_INTEGER, -1, Number.MAX_SAFE_INTEGER])(
    "accepts safe epoch %s and an inclusive startsAt at that epoch", (at) => {
      expect(core.evaluate({ action: "files.read", at, snapshot: {
        knownActions: ["files.read"], facts: [
          { permission: "files.read", effect: "grant", startsAt: at },
        ],
      } })).toEqual({ outcome: "allow", code: "granted", recognition: "known" });
    },
  );

  it("treats prototype-named dimensions as ordinary own scope data", () => {
    const scope = JSON.parse('{"__proto__":"a"}') as core.Scope;
    const input = { action: "files.read", at: 0, snapshot: {
      knownActions: ["files.read"], facts: [
        { permission: "files.read", effect: "grant" as const, scope },
      ],
    } };
    expect(core.evaluate({ ...input, scope }).outcome).toBe("allow");
    expect(core.evaluate({ ...input, scope: JSON.parse('{"__proto__":"b"}') }).code)
      .toBe("no-applicable-grant");
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
    ["unsafe negative clock", { action: "files.read", at: Number.MIN_SAFE_INTEGER - 1, snapshot: { facts: [], knownActions: [] } }],
    ["non-array facts", { action: "files.read", at: 0, snapshot: { facts: { length: 0 }, knownActions: [] } }],
    ["sparse facts", { action: "files.read", at: 0, snapshot: { facts: new Array(1), knownActions: [] } }],
    ["sparse definitions", { action: "files.read", at: 0, snapshot: { facts: [], knownActions: new Array(1) } }],
    ["invalid request scope", { action: "files.read", at: 0, scope: { tenant: 1 }, snapshot: { facts: [], knownActions: [] } }],
    ["empty dimension name", { action: "files.read", at: 0, scope: { "": "a" }, snapshot: { facts: [], knownActions: [] } }],
    ["unsafe negative start", { action: "files.read", at: 0, snapshot: { facts: [{ permission: "files.read", effect: "grant", startsAt: Number.MIN_SAFE_INTEGER - 1 }], knownActions: [] } }],
    ["unsafe positive start", { action: "files.read", at: 0, snapshot: { facts: [{ permission: "files.read", effect: "grant", startsAt: Number.MAX_SAFE_INTEGER + 1 }], knownActions: [] } }],
    ["invalid provenance", { action: "files.read", at: 0, snapshot: { facts: [{ permission: "files.read", effect: "grant", provenanceId: 1 }], knownActions: [] } }],
    ["symbol-keyed input", { action: "files.read", at: 0, [Symbol("unsupported")]: true, snapshot: { facts: [], knownActions: [] } }],
    ["trailing-dot pattern", { action: "files.read", at: 0, snapshot: { facts: [{ permission: "files.", effect: "grant" }], knownActions: [] } }],
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

  it("ignores array-subclass prototype method replacements", () => {
    class Facts extends Array<core.EffectiveFact> {}
    class Definitions extends Array<string> {}
    Object.defineProperty(Facts.prototype, "filter", {
      value: () => [{ permission: "files.read", effect: "grant" }],
    });
    Object.defineProperty(Definitions.prototype, "includes", { value: () => true });
    expect(core.evaluate({ action: "files.read", at: 0, snapshot: {
      knownActions: ["files.read"], facts: new Facts({ permission: "files.read", effect: "deny" }),
    } })).toEqual({ outcome: "deny", code: "explicit-deny" });
    expect(core.evaluate({ action: "files.delete", at: 0, snapshot: {
      knownActions: new Definitions("files.read"), facts: [{ permission: "*", effect: "grant" }],
    } })).toEqual({ outcome: "deny", code: "unknown-action" });
  });

  it("rejects accessor array indices without invoking them", () => {
    let reads = 0;
    const facts: core.EffectiveFact[] = [];
    Object.defineProperty(facts, "0", { get() {
      reads += 1;
      return { permission: "files.read", effect: "grant" };
    } });
    expect(() => core.evaluate({ action: "files.read", at: 0,
      snapshot: { knownActions: ["files.read"], facts },
    })).toThrow(core.AuthorizationFault);
    expect(reads).toBe(0);
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

  it("applies risk policy exceptions only to active wildcard grants and preserves denial precedence", () => {
    const policy = { riskLevels: ["low", "critical"], byRisk: { critical: { unknownPermissions: "allow-if-wildcard-granted" } } };
    const input = { action: "runtime.read", at: 5, policy, actionPolicy: { risk: "critical" }, snapshot: {
      knownActions: [], facts: [{ permission: "runtime.*", effect: "grant" as const }],
    } };
    expect(core.evaluate(input as never)).toEqual({ outcome: "allow", code: "granted", recognition: "wildcard-exception" });
    expect(core.evaluate({ ...input, snapshot: { ...input.snapshot, facts: [{ permission: "runtime.read", effect: "grant" as const }] } } as never))
      .toEqual({ outcome: "deny", code: "unknown-action" });
    expect(core.evaluate({ ...input, snapshot: { ...input.snapshot, facts: [...input.snapshot.facts, { permission: "runtime.*", effect: "deny" as const }] } } as never))
      .toEqual({ outcome: "deny", code: "explicit-deny" });
  });

  it("uses exact then longest namespace then global risk rules", () => {
    const input = { action: "files.admin.read", at: 0, snapshot: { knownActions: [], facts: [
      { permission: "files.*", effect: "grant" as const },
    ] }, policy: {
      riskLevels: ["low", "critical"],
      risk: { "*": "low", "files.*": "critical", "files.admin.read": "low" },
      byRisk: { critical: { unknownPermissions: "allow-if-wildcard-granted" } },
    } };
    expect(core.evaluate(input as never)).toEqual({ outcome: "deny", code: "unknown-action" });
    expect(core.evaluate({ ...input, action: "files.other" } as never).outcome).toBe("allow");
    expect(core.evaluate({ ...input, action: "other.read" } as never).outcome).toBe("deny");
  });

  it("rejects duplicate risk labels and malformed policy rules at runtime", () => {
    const base = { action: "files.read", at: 0, snapshot: { knownActions: ["files.read"], facts: [] } };
    expect(() => core.evaluate({ ...base, policy: { riskLevels: ["low", "low"] } } as never)).toThrow(core.AuthorizationFault);
    expect(() => core.evaluate({ ...base, policy: { riskLevels: ["low"], defaults: { unknownPermissions: "allow-if-wildcard-granty" } } } as never)).toThrow(core.AuthorizationFault);
    expect(() => core.evaluate({ ...base, policy: { riskLevels: ["low"], risk: { "files.**": "low" } } } as never)).toThrow(core.AuthorizationFault);
    expect(() => core.evaluate({ ...base, policy: { riskLevels: ["low"], risk: { "files.*": "critical" } } } as never)).toThrow(core.AuthorizationFault);
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
