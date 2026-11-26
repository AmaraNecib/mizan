import assert from "node:assert/strict";
import { expandRoles } from "@mizan/core/normalization";
const direct = Array.from({ length: 150_000 }, () => ({ permission: "records.edit", effect: "deny" }));
assert.equal(expandRoles([], [], direct).facts.length, 150_000);
console.log("Node large direct-fact snapshot passed");
