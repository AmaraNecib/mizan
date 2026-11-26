import type { EffectiveFact } from "../src/direct-evaluation.js";
import { expandRoles, type RoleAssignment, type RoleDefinition } from "@mizan/core/normalization";

const definitions: readonly RoleDefinition[] = [
  { name: "records-editor", permissions: [{ permission: "records.edit", effect: "grant" }] },
];
const assignments: readonly RoleAssignment[] = [{ roleName: "records-editor", expiresAt: 1_800_000_000_000 }];
const directFacts: readonly EffectiveFact[] = [{ permission: "records.edit", effect: "deny" }];

const normalized = expandRoles(definitions, assignments, directFacts);
const facts: readonly EffectiveFact[] = normalized.facts;
void facts;
// @ts-expect-error Role assignments must reference a role name, not a host decision.
expandRoles(definitions, [{ roleName: 42 }]);
