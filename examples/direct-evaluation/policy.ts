import type { AuthorizationPolicy } from "@mizan/core";

export type ExampleRisk = "low" | "critical";
export const importedPolicy = {
  riskLevels: ["low", "critical"],
  defaults: { unknownPermissions: "deny" },
  risk: { "reports.*": "critical" },
  byRisk: { critical: { unknownPermissions: "allow-if-wildcard-granted" } },
} as const satisfies AuthorizationPolicy<ExampleRisk>;
