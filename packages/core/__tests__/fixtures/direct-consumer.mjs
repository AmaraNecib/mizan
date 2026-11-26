// Run after building core: node packages/core/__tests__/fixtures/direct-consumer.mjs
import assert from "node:assert/strict";
import { evaluate, isAllowed, toPublic, AuthorizationFault } from "@mizan/core";

const decision = evaluate({
  action: "employees:read",
  at: 0,
  snapshot: {
    knownActions: ["employees:read"],
    facts: [{ permission: "employees:read", effect: "grant" }],
  },
});
assert.equal(isAllowed(decision), true);
assert.deepEqual(toPublic(decision), { allowed: true });
assert.equal(evaluate({
  action: "employees:delete",
  at: 0,
  snapshot: { knownActions: [], facts: [{ permission: "*", effect: "grant" }] },
}).code, "unknown-action");
assert.throws(() => evaluate({ action: "employees:read", at: Number.NaN, snapshot: { facts: [], knownActions: [] } }), AuthorizationFault);
console.log("Built ESM core consumer passed");
