import { describe, expect, it } from "bun:test";
import { resolve } from "node:path";
import { AuthorizationFault, evaluate, type EffectiveFact, type AuthorizationPolicy } from "@mizan/core";
import { importedPolicy } from "../../../examples/direct-evaluation/policy.js";

const base = { action: "reports.export", at: 10, snapshot: { knownActions: [], facts: [] } };
const grant: EffectiveFact = { permission: "reports.*", effect: "grant" };
const allow = { outcome: "allow", code: "granted", recognition: "wildcard-exception" };
const unknown = { outcome: "deny", code: "unknown-action" };
const policy = {
  riskLevels: ["low", "critical"],
  defaults: { unknownPermissions: "deny" },
  risk: { "*": "low", "reports.*": "critical" },
  byRisk: { critical: { unknownPermissions: "allow-if-wildcard-granted" } },
} as const satisfies AuthorizationPolicy<"low" | "critical">;

function decide(facts: readonly EffectiveFact[]) {
  return evaluate({ ...base, policy, snapshot: { knownActions: [], facts } });
}

// Runtime boundary tests deliberately supply untyped JavaScript-shaped values.
function runtime(input: unknown) {
  return evaluate(input as never);
}

describe("typed direct policies", () => {
  it("runs the public-core example with imported and inline policies", () => {
    const result = Bun.spawnSync(["bun", "run", "--filter", "@mizan/example-direct-evaluation", "start"], {
      cwd: resolve(import.meta.dir, "../../.."),
    });
    expect(result.exitCode).toBe(0);
    const output = new TextDecoder().decode(result.stdout);
    expect(output).toContain("Imported policy");
    expect(output).toContain("Inline policy");
    expect(output.match(/wildcard-exception/g)?.length).toBe(2);
  });

  it("accepts an imported policy and a built-in override without explicit policy", () => {
    expect(evaluate({ ...base, policy: importedPolicy, snapshot: { knownActions: [], facts: [grant] } })).toEqual(allow);
    expect(evaluate({ ...base, actionPolicy: { risk: "high", unknownPermissions: "allow-if-wildcard-granted" }, snapshot: { knownActions: [], facts: [grant] } })).toEqual(allow);
    expect(() => runtime({ ...base, actionPolicy: { risk: "critical" } })).toThrow(AuthorizationFault);
  });

  it("resolves behavior through action, byRisk, defaults, and built-in deny", () => {
    const input = { ...base, snapshot: { knownActions: [], facts: [grant] }, policy };
    expect(evaluate(input)).toEqual(allow);
    expect(evaluate({ ...input, actionPolicy: { unknownPermissions: "deny" } })).toEqual(unknown);
    expect(evaluate({ ...input, actionPolicy: { risk: "low" } })).toEqual(unknown);
    expect(evaluate({ ...input, policy: { ...policy, defaults: { unknownPermissions: "allow-if-wildcard-granted" }, byRisk: { critical: { unknownPermissions: "deny" } } } })).toEqual(unknown);
    expect(evaluate({ ...input, policy: { ...policy, byRisk: { critical: {} }, defaults: { unknownPermissions: "allow-if-wildcard-granted" } } })).toEqual(allow);
    expect(evaluate({ ...input, policy: { riskLevels: ["low"] } })).toEqual(unknown);
    expect(evaluate({ ...input, policy: undefined })).toEqual(unknown);
  });

  it("resolves exact over nested namespace over global without depending on insertion order", () => {
    const risk = { "reports.admin.export": "low", "reports.*": "low", "*": "critical", "reports.admin.*": "critical" } as const;
    const input = { ...base, policy: { ...policy, risk }, snapshot: { knownActions: [], facts: [{ permission: "*", effect: "grant" as const }] } };
    expect(evaluate({ ...input, action: "reports.admin.read" })).toEqual(allow);
    expect(evaluate({ ...input, action: "reports.admin.export" })).toEqual(unknown);
    expect(evaluate({ ...input, action: "reports.read" })).toEqual(unknown);
    expect(evaluate({ ...input, action: "other.read" })).toEqual(allow);
    expect(evaluate({ ...input, action: "reports" })).toEqual(allow);
  });

  it.each([
    ["exact", { permission: "reports.export", effect: "grant" }],
    ["wrong namespace", { permission: "other.*", effect: "grant" }],
    ["not started", { ...grant, startsAt: 11 }],
    ["expired", { ...grant, expiresAt: 10 }],
    ["equal bounds", { ...grant, startsAt: 10, expiresAt: 10 }],
    ["scoped without request", { ...grant, scope: { tenant: "a" } }],
  ] as const)("does not use %s facts for wildcard exceptions", (_name, fact) => {
    expect(decide([fact])).toEqual(unknown);
  });

  it("requires matching scope and treats half-open wildcard bounds exactly", () => {
    const input = { ...base, policy, scope: { tenant: "a", project: "p" }, snapshot: { knownActions: [], facts: [{ ...grant, scope: { tenant: "a" }, startsAt: 10, expiresAt: 11 }] } };
    expect(evaluate(input)).toEqual(allow);
    expect(evaluate({ ...input, at: 11 })).toEqual(unknown);
    expect(evaluate({ ...input, scope: { tenant: "b" } })).toEqual(unknown);
    expect(evaluate({ ...input, scope: undefined })).toEqual(unknown);
    expect(decide([{ ...grant, scope: {} }])).toEqual(allow);
    expect(decide([{ permission: "*", effect: "grant" }])).toEqual(allow);
  });

  it("never grants from labels and keeps known recognition separate", () => {
    expect(decide([])).toEqual(unknown);
    expect(evaluate({ ...base, policy, snapshot: { knownActions: [base.action], facts: [] } })).toEqual({ outcome: "deny", code: "no-applicable-grant" });
    expect(evaluate({ ...base, policy, actionPolicy: { unknownPermissions: "deny" }, snapshot: { knownActions: [base.action], facts: [grant] } })).toEqual({ outcome: "allow", code: "granted", recognition: "known" });
  });

  it("applies explicit denials before permissive overrides and ignores only inactive or out-of-scope denials", () => {
    for (const permission of ["*", "reports.*", base.action]) {
      expect(decide([grant, { permission, effect: "deny" }])).toEqual({ outcome: "deny", code: "explicit-deny" });
    }
    expect(decide([grant, { ...grant, effect: "deny", expiresAt: 10 }])).toEqual(allow);
    expect(decide([grant, { ...grant, effect: "deny", startsAt: 10, expiresAt: 10 }])).toEqual(allow);
    expect(decide([grant, { ...grant, effect: "deny", scope: { tenant: "b" } }])).toEqual(allow);
  });

  it.each([
    null, [], {}, { riskLevels: null }, { riskLevels: ["low", "low"] }, { riskLevels: [""] },
    { riskLevels: [1] }, { riskLevels: ["low"], extra: true },
    { riskLevels: ["low"], defaults: { unknownPermissions: "typo" } },
    { riskLevels: ["low"], defaults: { typo: "deny" } },
    { riskLevels: ["low"], defaults: null },
    { riskLevels: ["low"], byRisk: { critical: {} } },
    { riskLevels: ["low"], byRisk: { low: { unknownPermissions: "typo" } } },
    { riskLevels: ["low"], byRisk: { low: { extra: "deny" } } },
    { riskLevels: ["low"], risk: { "irrelevant.*": "critical" } },
    ...["reports.**", "reports.*.read", "reports..read", " reports.*", ""].map((pattern) => ({ riskLevels: ["low"], risk: { [pattern]: "low" } })),
  ].map((value) => [value]))("rejects malformed policy %# even when unrelated to the requested key", (invalidPolicy) => {
    expect(() => runtime({ ...base, policy: invalidPolicy })).toThrow(AuthorizationFault);
  });

  it.each([
    null, [], { risk: "critical" }, { unknownPermissions: "typo" }, { unknownPermission: "deny" },
  ].map((value) => [value]))("rejects malformed action override %#", (actionPolicy) => {
    expect(() => runtime({ ...base, policy: { riskLevels: ["low"] }, actionPolicy })).toThrow(AuthorizationFault);
  });

  it("rejects accessor and symbol policy fields without executing getters", () => {
    let calls = 0;
    const accessor = { get unknownPermissions() { calls += 1; return "deny"; } };
    expect(() => runtime({ ...base, policy: { riskLevels: ["low"], defaults: accessor } })).toThrow(AuthorizationFault);
    expect(calls).toBe(0);
    expect(() => runtime({ ...base, policy: { riskLevels: ["low"], defaults: { [Symbol("hidden")]: "deny" } } })).toThrow(AuthorizationFault);
  });

  it("accepts well-formed unmatched patterns as inert and prototype-named custom labels", () => {
    expect(evaluate({ ...base, policy: { riskLevels: ["critical"], risk: { "unused.*": "critical" } }, snapshot: { knownActions: [], facts: [grant] } })).toEqual(unknown);
    expect(runtime({ ...base, policy: JSON.parse('{"riskLevels":["__proto__"],"risk":{"*":"__proto__"},"byRisk":{"__proto__":{"unknownPermissions":"allow-if-wildcard-granted"}}}'), snapshot: { knownActions: [], facts: [grant] } })).toEqual(allow);
  });
});
