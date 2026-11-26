import { evaluate } from "@mizan/core";
import { importedPolicy } from "./policy.js";

const decision = evaluate({
  action: "reports.export",
  at: Date.now(),
  policy: importedPolicy,
  snapshot: {
    knownActions: [],
    facts: [{ permission: "reports.*", effect: "grant" }],
  },
});

console.log("Imported policy", decision);

const inlineDecision = evaluate({
  action: "reports.preview",
  at: 0,
  policy: { riskLevels: ["low", "critical"], defaults: { unknownPermissions: "deny" } },
  actionPolicy: { risk: "low", unknownPermissions: "allow-if-wildcard-granted" },
  snapshot: {
    knownActions: [],
    facts: [{ permission: "reports.*", effect: "grant" }],
  },
});
console.log("Inline policy", inlineDecision);
