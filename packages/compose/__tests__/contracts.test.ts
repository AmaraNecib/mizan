import { expect, it } from "bun:test";
import { accept, AuthorizationFault, createAuthorizer, type SourceOutcome, type SourceQuery } from "@mizan/compose";

const bound = { subjectId: "u", partitionKey: "p", scope: { tenant: "a" } };
function complete(query: SourceQuery<unknown>, dataAsOf = 100): SourceOutcome {
  return {
    status: "complete", binding: { ...bound, action: query.action }, contribution: "permissions",
    recognitionDomains: ["catalog"], snapshot: {
      facts: [{ permission: "files.read", effect: "grant" }], knownActions: [],
    }, assurance: { consistency: "current", dataAsOf },
  };
}
function authorizer(resolve: (query: SourceQuery<unknown>) => SourceOutcome | Promise<SourceOutcome>, clock = () => 110, maxAgeMs = 1000) {
  return createAuthorizer({
    policy: { riskLevels: ["low"] }, bindContext: () => bound,
    actions: { "files.read": { source: accept({ contribution: "permissions", recognitionDomains: ["catalog"], resolve },
      { consistency: "current", maxAgeMs }), recognitionRequirements: ["catalog"] } }, clock,
  });
}

it("accepts evidence observed during acquisition rather than measuring age at request start", async () => {
  let now = 100;
  const handle = authorizer(async query => { now = 110; return complete(query, 105); }, () => now).forContext({});
  expect(await handle.decide("files.read")).toMatchObject({ outcome: "allow" });
});

it("rejects a decreasing clock instead of deactivating a denial", async () => {
  let reads = 0;
  const handle = authorizer(query => ({ ...complete(query, 0), snapshot: { knownActions: [], facts: [
    { permission: "files.read", effect: "grant" }, { permission: "files.read", effect: "deny", startsAt: 75 },
  ] } } as SourceOutcome), () => reads++ === 0 ? 100 : 50).forContext({});
  await expect(handle.decide("files.read")).rejects.toBeInstanceOf(AuthorizationFault);
});

it("validates malformed complete facts even when their assurance is insufficient", async () => {
  const handle = authorizer(query => ({ ...complete(query, 0), snapshot: {
    knownActions: [], facts: [{ permission: "*", effect: "deny", schedule: {} }],
  } } as never), () => 110, 0).forContext({});
  await expect(handle.decide("files.read")).rejects.toBeInstanceOf(AuthorizationFault);
});

it("source callbacks cannot rewrite the bound query or mutate the handle scope", async () => {
  const handle = authorizer(query => {
    try { (query.scope as Record<string, string>).tenant = "other"; } catch { /* A frozen query is also valid. */ }
    try { (query as { partitionKey: string }).partitionKey = "other"; } catch { /* Keep the original binding. */ }
    return { ...complete(query), binding: { ...bound, partitionKey: "other", scope: { tenant: "other" }, action: query.action } };
  }).forContext({});
  await expect(handle.decide("files.read")).rejects.toBeInstanceOf(AuthorizationFault);
});

it("validates malformed snapshots through can with the same public fault class", async () => {
  const handle = authorizer(query => ({ ...complete(query), snapshot: {
    knownActions: [], facts: [{ permission: "files.read", effect: "invalid" }],
  } } as never)).forContext({});
  await expect(handle.can("files.read")).rejects.toBeInstanceOf(AuthorizationFault);
});
