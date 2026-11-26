import type { AuthorizationPolicy } from "./direct-evaluation.js";

export type FixtureRisk = "low" | "critical";
export const importedPolicy = {
  riskLevels: ["low", "critical"],
  defaults: { unknownPermissions: "deny" },
  risk: { "reports.*": "critical" },
  byRisk: { critical: { unknownPermissions: "allow-if-wildcard-granted" } },
} as const satisfies AuthorizationPolicy<FixtureRisk>;
