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
// @ts-expect-error Unsupported schedules must not enter the normalization contract.
expandRoles(definitions, [{ roleName: "records-editor", schedule: {} }]);
// @ts-expect-error Unknown effective fact kinds cannot be normalized.
expandRoles([{ name: "role", permissions: [{ permission: "x", effect: "allow" }] }], []);
// @ts-expect-error Direct facts must retain a recognized effect.
expandRoles([], [], [{ permission: "x", effect: "revoke" }]);
// @ts-expect-error Scope dimensions are strings, not host objects.
expandRoles(definitions, [{ roleName: "records-editor", scope: { org: 1 } }]);
// @ts-expect-error The result is readonly at the public type seam.
normalized.facts.push({ permission: "x", effect: "grant" });
