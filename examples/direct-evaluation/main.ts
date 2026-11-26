import { evaluate } from "@mizan/core";
import { importedPolicy } from "../../packages/core/src/policy-fixture.js";

const decision = evaluate({
  action: "reports.export",
  at: Date.now(),
  policy: importedPolicy,
  snapshot: {
    knownActions: [],
    facts: [{ permission: "reports.*", effect: "grant" }],
  },
});

console.log(decision);
