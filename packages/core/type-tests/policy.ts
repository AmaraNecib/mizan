import { evaluate, type AuthorizationPolicy, type ActionPolicy, type EvaluationInput } from "@mizan/core";
import { importedPolicy } from "../../../examples/direct-evaluation/policy.js";

const facts = { action: "reports.read", at: 0, snapshot: { knownActions: [], facts: [] } };
const importedAction = { risk: "critical" } as const satisfies ActionPolicy<"low" | "critical">;
evaluate({ ...facts, policy: importedPolicy, actionPolicy: importedAction });
evaluate({ ...facts, policy: { riskLevels: ["low", "critical"], byRisk: { critical: { unknownPermissions: "allow-if-wildcard-granted" } } }, actionPolicy: { risk: "critical" } });
evaluate(facts);
function check(input: EvaluationInput) { return evaluate(input); }
check(facts);
function checkCustom(input: EvaluationInput<"custom">) { return evaluate(input); }
checkCustom({ ...facts, policy: { riskLevels: ["custom"] } });
// @ts-expect-error annotating an input does not register its custom risk
checkCustom({ ...facts, actionPolicy: { risk: "custom" } });
// @ts-expect-error an explicit type argument does not register a custom risk either
evaluate<readonly ["custom"]>({ ...facts, actionPolicy: { risk: "custom" } });
// @ts-expect-error even a built-in label must be registered in an explicit policy
evaluate({ ...facts, policy: { riskLevels: ["low"] }, actionPolicy: { risk: "high" } });
evaluate({ ...facts, actionPolicy: { risk: "high", unknownPermissions: "deny" } });
const reusable: AuthorizationPolicy<"custom"> = { riskLevels: ["custom"] };
evaluate({ ...facts, policy: reusable, actionPolicy: { risk: "custom" } });

// @ts-expect-error imported registration cannot be widened by an inline action
evaluate({ ...facts, policy: importedPolicy, actionPolicy: { risk: "urgent" } });
// @ts-expect-error inline registration cannot be widened by an inline action
evaluate({ ...facts, policy: { riskLevels: ["low"] }, actionPolicy: { risk: "urgent" } });
// @ts-expect-error risk rules cannot widen inline registration
evaluate({ ...facts, policy: { riskLevels: ["low"], risk: { "*": "urgent" } } });
// @ts-expect-error byRisk keys cannot widen inline registration
evaluate({ ...facts, policy: { riskLevels: ["low"], byRisk: { urgent: { unknownPermissions: "deny" } } } });
// @ts-expect-error action risk without explicit registration uses only built-in labels
evaluate({ ...facts, actionPolicy: { risk: "urgent" } });
// @ts-expect-error unknown behavior strings are closed in inline defaults
evaluate({ ...facts, policy: { riskLevels: ["low"], defaults: { unknownPermissions: "allow-if-wildcard-granty" } } });
// @ts-expect-error unknown behavior strings are closed in byRisk
evaluate({ ...facts, policy: { riskLevels: ["low"], byRisk: { low: { unknownPermissions: "allow-if-wildcard-granty" } } } });
// @ts-expect-error unknown behavior strings are closed in action overrides
evaluate({ ...facts, policy: importedPolicy, actionPolicy: { unknownPermissions: "allow-if-wildcard-granty" } });
// @ts-expect-error reusable policy must use the declared closed behavior union
const invalidImported: AuthorizationPolicy<"low"> = { riskLevels: ["low"], defaults: { unknownPermissions: "typo" } };
void invalidImported;
