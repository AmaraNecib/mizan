import { expect, it } from "bun:test";
import { accept, AuthorizationFault, createAuthorizer, type EvidencePlan, type SourceOutcome, type SourceQuery } from "@mizan/compose";
import type { AuthorizationSnapshot } from "@mizan/core";

const binding = { subjectId: "u", partitionKey: "p", scope: {} };
const requirements = { consistency: "current", maxAgeMs: 0 } as const;
const grant = { permission: "read", effect: "grant" } as const;
const denial = { permission: "read", effect: "deny" } as const;

function evidence(query: SourceQuery<unknown>, snapshot: AuthorizationSnapshot): Extract<SourceOutcome, { status: "complete" }> {
  return {
    status: "complete", binding: { ...binding, action: query.action }, contribution: "permissions",
    recognitionDomains: [], snapshot, assurance: { consistency: "current", dataAsOf: 100 },
  };
}
function planFor(snapshot: AuthorizationSnapshot): EvidencePlan<unknown> {
  return accept({ contribution: "permissions", recognitionDomains: [], resolve: query => evidence(query, snapshot) }, requirements);
}
function handleFor(plan: EvidencePlan<unknown>) {
  const definition = { source: plan, recognitionRequirements: [] };
  return createAuthorizer({
    bindContext: () => binding, policy: { riskLevels: ["low"] }, actions: { read: definition },
    routes: { "*": definition }, clock: () => 100,
  }).forContext({});
}
const query: SourceQuery<unknown> = { ...binding, action: "read", context: {}, startedAt: 100 };

it("accepts 10,000 facts without dropping the last denial and rejects an additional fact", async () => {
  const facts = [...Array.from({ length: 9_999 }, () => grant), denial];
  const plan = planFor({ facts, knownActions: [] });
  await expect(handleFor(plan).decide("read")).resolves.toEqual({ outcome: "deny", code: "explicit-deny" });
  facts.push(grant);
  await expect(plan.resolve(query)).rejects.toBeInstanceOf(AuthorizationFault);
});

it("accepts 10,000 known actions and rejects an additional action through both public boundaries", async () => {
  const knownActions = [...Array.from({ length: 9_999 }, () => "other"), "runtime.read"];
  const plan = planFor({ facts: [{ permission: "runtime.read", effect: "grant" }], knownActions });
  await expect(handleFor(plan).decideDynamic({ action: "runtime.read" })).resolves.toMatchObject({ outcome: "allow" });
  knownActions.push("extra");
  await expect(plan.resolve(query)).rejects.toBeInstanceOf(AuthorizationFault);
  const customPlan: EvidencePlan<unknown> = {
    contributions: ["permissions"], recognitionDomains: [],
    resolve: current => ({ status: "complete", selected: [{
      evidence: evidence(current, { facts: [grant], knownActions }), requirements,
    }] }),
  };
  await expect(handleFor(customPlan).can("read")).rejects.toBeInstanceOf(AuthorizationFault);
});

it("counts string values and property names together across facts and known actions", async () => {
  // The grant contributes 25 units: two field names and the values "read" and "grant".
  const knownActions = Array.from({ length: 1_000 }, () => "x".repeat(1_000));
  knownActions[0] = "x".repeat(975);
  await expect(planFor({ facts: [grant], knownActions }).resolve(query)).resolves.toMatchObject({ status: "complete" });
  knownActions[0] += "x";
  await expect(planFor({ facts: [grant], knownActions }).resolve(query)).rejects.toBeInstanceOf(AuthorizationFault);
});

it("counts repeated strings against the shared 1,000,000 UTF-16 code unit budget", async () => {
  const knownActions = Array.from({ length: 1_000 }, () => "x".repeat(1_000));
  await expect(planFor({ facts: [], knownActions }).resolve(query)).resolves.toMatchObject({ status: "complete" });
  knownActions[0] += "x";
  await expect(planFor({ facts: [], knownActions }).resolve(query)).rejects.toBeInstanceOf(AuthorizationFault);
});

it("shares the 100,000 entry budget across facts, scopes and known actions, including repeated scopes", async () => {
  const scope = Object.fromEntries(Array.from({ length: 996 }, (_, index) => [`d${index}`, "x"]));
  // Each occurrence has one fact slot, three fact properties and 996 scope properties.
  const facts = Array.from({ length: 100 }, () => ({ ...grant, scope }));
  await expect(planFor({ facts, knownActions: [] }).resolve(query)).resolves.toMatchObject({ status: "complete" });
  await expect(planFor({ facts, knownActions: ["read"] }).resolve(query)).rejects.toBeInstanceOf(AuthorizationFault);
});

it("validates selected receipt containers without invoking accessors or ignoring extra fields", async () => {
  let reads = 0;
  const receipt = { evidence: evidence(query, { facts: [grant], knownActions: [] }), requirements };
  const accessor: unknown[] = [];
  Object.defineProperty(accessor, "0", { get: () => { reads += 1; return receipt; } });
  const extra = Object.assign([receipt], { extra: true });
  const inherited = [receipt];
  Object.setPrototypeOf(inherited, {});
  for (const selected of [accessor, extra, inherited, new Array(1), [], [receipt, receipt]]) {
    const plan: EvidencePlan<unknown> = {
      contributions: ["permissions"], recognitionDomains: [], resolve: () => ({ status: "complete", selected } as never),
    };
    await expect(handleFor(plan).decide("read")).rejects.toBeInstanceOf(AuthorizationFault);
  }
  expect(reads).toBe(0);
});

it("copies custom plan snapshots before the final clock callback can mutate the returned evidence", async () => {
  const facts = [grant, denial];
  const plan: EvidencePlan<unknown> = {
    contributions: ["permissions"], recognitionDomains: [], resolve: current => ({
      status: "complete", selected: [{ evidence: evidence(current, { facts, knownActions: [] }), requirements }],
    }),
  };
  let samples = 0;
  const handle = createAuthorizer({
    bindContext: () => binding, policy: { riskLevels: ["low"] },
    actions: { read: { source: plan, recognitionRequirements: [] } },
    clock: () => { if (++samples === 2) facts.pop(); return 100; },
  }).forContext({});
  await expect(handle.decide("read")).resolves.toEqual({ outcome: "deny", code: "explicit-deny" });
});
