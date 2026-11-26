import assert from "node:assert/strict";
import { accept, createAuthorizer } from "@mizan/compose";

let calls = 0;
const source = {
  contribution: "permissions",
  recognitionDomains: ["catalog"],
  resolve: async (query) => {
    calls += 1;
    if (query.action === "runtime.offline") return { status: "unavailable", code: "offline" };
    const grant = query.action === "files.read" || query.action === "runtime.read";
    return {
      status: "complete",
      binding: { subjectId: "u1", partitionKey: "t1", action: query.action, scope: { tenant: "t1" } },
      contribution: "permissions",
      recognitionDomains: ["catalog"],
      snapshot: {
        knownActions: ["files.read", "runtime.read", "runtime.denied"],
        facts: grant ? [{ permission: query.action, effect: "grant" }] : [],
      },
      assurance: { consistency: "current", dataAsOf: 100 },
    };
  },
};
const plan = accept(source, { consistency: "current", maxAgeMs: 0 });
const definition = { source: plan, recognitionRequirements: ["catalog"] };
const authorizer = createAuthorizer({
  policy: { riskLevels: ["low"] },
  bindContext: () => ({ subjectId: "u1", partitionKey: "t1", scope: { tenant: "t1" } }),
  actions: { "files.read": definition },
  routes: { "runtime.*": definition },
  clock: () => 100,
});
const request = authorizer.forContext({});
assert.deepEqual(await request.decide("files.read"), { outcome: "allow", code: "granted", recognition: "known" });
assert.equal(await request.can("files.read"), true);
assert.deepEqual(await request.decideDynamic({ action: "runtime.read" }), { outcome: "allow", code: "granted", recognition: "known" });
assert.deepEqual(await request.decideDynamic({ action: "runtime.denied" }), { outcome: "deny", code: "no-applicable-grant" });
assert.equal(await request.can("runtime.denied"), false);
assert.deepEqual(await request.decideDynamic({ action: "runtime.offline" }), { outcome: "indeterminate", code: "evidence-unavailable" });
assert.equal(await request.can("runtime.offline"), false);
assert.equal(await request.can("files.read"), true);
assert.equal(calls, 8);
console.log("packed consumer: allow, deny, indeterminate, dynamic recognition, false projection, and reacquisition passed");
