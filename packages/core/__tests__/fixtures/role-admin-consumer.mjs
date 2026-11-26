import assert from "node:assert/strict";
import { evaluate } from "@mizan/core";
import { expandRoles } from "@mizan/core/normalization";

// Generic adapter mapping, not a storage or administrative-service contract.
const facts = expandRoles(
  [{ name: "records-editor", permissions: [{ permission: "records.edit", effect: "grant" }] }],
  [{ roleName: "records-editor", scope: { organization: "north" }, expiresAt: 500 }],
  [{ permission: "records.edit", effect: "deny", scope: { organization: "north" }, startsAt: 200, expiresAt: 500 }],
).facts;

assert.equal(evaluate({
  action: "records.edit",
  at: 250,
  scope: { organization: "north" },
  snapshot: { facts, knownActions: ["records.edit"] },
}).code, "explicit-deny");
assert.equal(evaluate({
  action: "records.edit",
  at: 500,
  scope: { organization: "north" },
  snapshot: { facts, knownActions: ["records.edit"] },
}).code, "no-applicable-grant");
console.log("Generic role administration adapter mapping passed");
