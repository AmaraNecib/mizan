import { evaluate, type AuthorizationPolicy } from "./index.js";

const appPolicy = {
  riskLevels: ["low", "critical"],
  byRisk: { critical: { unknownPermissions: "allow-if-wildcard-granted" } },
} as const satisfies AuthorizationPolicy<"low" | "critical">;

evaluate({
  action: "reports.read",
  at: 0,
  snapshot: { knownActions: [], facts: [] },
  policy: appPolicy,
  actionPolicy: { risk: "critical" },
});

// @ts-expect-error unregistered inline risk must fail typechecking
evaluate({ action: "reports.read", at: 0, snapshot: { knownActions: [], facts: [] }, policy: appPolicy, actionPolicy: { risk: "urgent" } });
// @ts-expect-error unknown behavior strings are closed
evaluate({ action: "reports.read", at: 0, snapshot: { knownActions: [], facts: [] }, policy: { riskLevels: ["low"], defaults: { unknownPermissions: "allow-if-wildcard-granty" } } });
