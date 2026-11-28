import { expect, it } from "bun:test";
import { accept, AuthorizationFault, createAuthorizer, type EvidencePlan, type SourceOutcome, type SourceQuery } from "@mizan/compose";

const binding = { subjectId: "u", partitionKey: "p", scope: {} };
const requirements = { consistency: "current", maxAgeMs: 0 } as const;
const query: SourceQuery<unknown> = { ...binding, action: "read", context: {}, startedAt: 100 };

function evidence(current: SourceQuery<unknown>, domains: readonly string[]): Extract<SourceOutcome, { status: "complete" }> {
  return {
    status: "complete", binding: { ...binding, action: current.action }, contribution: "permissions",
    recognitionDomains: domains, snapshot: {
      facts: [{ permission: "*", effect: "grant" }], knownActions: ["runtime.read"],
    }, assurance: { consistency: "current", dataAsOf: 100 },
  };
}
function planFor(declared: readonly string[], returned = declared): EvidencePlan<unknown> {
  return accept({
    contribution: "permissions", recognitionDomains: declared, resolve: current => evidence(current, returned),
  }, requirements);
}
function handleFor(plan: EvidencePlan<unknown>, recognitionRequirements: readonly string[] = []) {
  const definition = { source: plan, recognitionRequirements };
  return createAuthorizer({
    policy: { riskLevels: ["low"] }, bindContext: () => binding,
    actions: { read: definition }, routes: { "*": definition }, clock: () => 100,
  }).forContext({});
}

it("rejects source and structural-plan domain cardinality mismatches before inspecting entries", async () => {
  const mismatched = ["catalog", "extra"];
  Object.defineProperty(mismatched, "0", { get() { throw new Error("entry must not be read"); } });
  await expect(planFor(["catalog"], mismatched).resolve(query))
    .rejects.toThrow("Source recognitionDomains do not match their declaration");
  const custom: EvidencePlan<unknown> = {
    contributions: ["permissions"], recognitionDomains: ["catalog"],
    resolve: current => ({ status: "complete", selected: [{ evidence: evidence(current, mismatched), requirements }] }),
  };
  await expect(handleFor(custom).can("read"))
    .rejects.toThrow("Source recognitionDomains do not match their declaration");
});

it("accepts 10,000 declared domains including required final coverage, but rejects another slot before inspecting it", async () => {
  const domains = Array.from({ length: 10_000 }, (_, index) => `domain-${index}`);
  await expect(handleFor(planFor(domains), ["domain-9999"]).decideDynamic({ action: "runtime.read" }))
    .resolves.toMatchObject({ outcome: "allow" });
  const tooMany = new Array<string>(10_001);
  expect(() => planFor(tooMany)).toThrow("maximum array length");
  const custom: EvidencePlan<unknown> = {
    contributions: ["permissions"], recognitionDomains: tooMany, resolve: () => ({ status: "miss" }),
  };
  expect(() => handleFor(custom)).toThrow(AuthorizationFault);
  expect(() => handleFor(planFor([]), tooMany)).toThrow("maximum array length");
});

it("bounds individual and combined domain text without truncation at source, plan and requirement construction", async () => {
  const atLimit = ["x".repeat(1_000_000)];
  await expect(planFor(atLimit).resolve(query)).resolves.toMatchObject({
    status: "complete", selected: [{ evidence: { recognitionDomains: atLimit } }],
  });
  for (const domains of [[atLimit[0]! + "x"], ["x".repeat(500_000), "y".repeat(500_001)]]) {
    expect(() => planFor(domains)).toThrow(AuthorizationFault);
    const custom: EvidencePlan<unknown> = {
      contributions: ["permissions"], recognitionDomains: domains, resolve: () => ({ status: "miss" }),
    };
    expect(() => handleFor(custom)).toThrow(AuthorizationFault);
    expect(() => handleFor(planFor([]), domains)).toThrow("maximum text budget");
  }
});

it("bounds returned text through both source and structural plan boundaries", async () => {
  const domains = ["x".repeat(1_000_001)];
  await expect(planFor(["catalog"], domains).resolve(query)).rejects.toBeInstanceOf(AuthorizationFault);
  const custom: EvidencePlan<unknown> = {
    contributions: ["permissions"], recognitionDomains: ["catalog"],
    resolve: current => ({ status: "complete", selected: [{ evidence: evidence(current, domains), requirements }] }),
  };
  await expect(handleFor(custom).decide("read")).rejects.toBeInstanceOf(AuthorizationFault);
});

it("rejects duplicate, reordered and substituted domains without treating them as valid coverage", async () => {
  const declared = ["catalog", "roles"];
  for (const domains of [["catalog", "catalog"], ["roles", "catalog"], ["catalog", "other"]]) {
    await expect(planFor(declared, domains).resolve(query)).rejects.toBeInstanceOf(AuthorizationFault);
    const custom: EvidencePlan<unknown> = {
      contributions: ["permissions"], recognitionDomains: declared,
      resolve: current => ({ status: "complete", selected: [{ evidence: evidence(current, domains), requirements }] }),
    };
    await expect(handleFor(custom).can("read")).rejects.toBeInstanceOf(AuthorizationFault);
  }
  expect(() => planFor(["catalog", "catalog"])).toThrow(AuthorizationFault);
  expect(() => handleFor(planFor(declared), ["catalog", "catalog"])).toThrow(AuthorizationFault);
});

it("rejects malformed domain arrays without invoking entry getters", async () => {
  let reads = 0;
  const accessor = ["catalog"];
  Object.defineProperty(accessor, "0", { get() { reads += 1; return "catalog"; } });
  const inherited = ["catalog"];
  Object.setPrototypeOf(inherited, {});
  for (const domains of [accessor, inherited, new Array<string>(1), [""], [42] as never,
    Object.assign(["catalog"], { extra: true }), Object.assign(["catalog"], { [Symbol("extra")]: true })]) {
    expect(() => planFor(domains)).toThrow(AuthorizationFault);
    await expect(planFor(["catalog"], domains).resolve(query)).rejects.toBeInstanceOf(AuthorizationFault);
    const custom: EvidencePlan<unknown> = {
      contributions: ["permissions"], recognitionDomains: ["catalog"],
      resolve: current => ({ status: "complete", selected: [{ evidence: evidence(current, domains), requirements }] }),
    };
    await expect(handleFor(custom).decideDynamic({ action: "runtime.read" })).rejects.toBeInstanceOf(AuthorizationFault);
  }
  expect(reads).toBe(0);
});

it("keeps empty domains valid and isolates required coverage from later declaration mutation", async () => {
  await expect(handleFor(planFor([])).can("read")).resolves.toBe(true);
  const domains = ["catalog", "roles"];
  const required = ["roles"];
  const plan = planFor(domains, ["catalog", "roles"]);
  const handle = handleFor(plan, required);
  domains[1] = "changed";
  required[0] = "changed";
  await expect(handle.decideDynamic({ action: "runtime.read" })).resolves.toEqual({
    outcome: "allow", code: "granted", recognition: "known",
  });
  expect(() => handleFor(planFor(["catalog"]), ["roles"])).toThrow(AuthorizationFault);
});
