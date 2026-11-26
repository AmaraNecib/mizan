import { AuthorizationFault } from "./direct-evaluation.js";
import type { EffectiveFact, Scope } from "./direct-evaluation.js";

export type RolePermission = EffectiveFact;

export type RoleDefinition = {
  readonly name: string;
  readonly permissions: readonly RolePermission[];
};

export type RoleAssignment = {
  readonly roleName: string;
  readonly scope?: Scope;
  readonly startsAt?: number;
  readonly expiresAt?: number;
  readonly provenanceId?: string;
};

export type NormalizationDiagnostic = {
  readonly code: "scope-conflict" | "empty-validity";
  readonly roleName: string;
  readonly permission: string;
};

export type ExpandRolesResult = {
  readonly facts: readonly EffectiveFact[];
  readonly diagnostics: readonly NormalizationDiagnostic[];
  readonly omittedDiagnostics: number;
};

const MAX_DIAGNOSTICS = 20;
const DEFINITION_KEYS = new Set(["name", "permissions"]);
const ASSIGNMENT_KEYS = new Set(["roleName", "scope", "startsAt", "expiresAt", "provenanceId"]);
const FACT_KEYS = new Set(["permission", "effect", "scope", "startsAt", "expiresAt", "provenanceId"]);

function invalid(message: string): never {
  throw new AuthorizationFault(message);
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return invalid(`${name} must be a plain data object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return invalid(`${name} must be a plain data object`);
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== "string" || descriptor === undefined || !("value" in descriptor)) {
      return invalid(`${name} must contain string-keyed data properties, not accessors`);
    }
    Object.defineProperty(result, key, { value: descriptor.value, enumerable: true });
  }
  return result;
}

function checkedRecord(value: unknown, keys: Set<string>, name: string): Record<string, unknown> {
  const copy = record(value, name);
  for (const key of Reflect.ownKeys(copy)) {
    if (typeof key !== "string" || !keys.has(key)) return invalid(`${name} contains an unsupported field`);
  }
  return copy;
}

function array(value: unknown, name: string): unknown[] {
  if (!Array.isArray(value)) return invalid(`${name} must be an array`);
  const length = Object.getOwnPropertyDescriptor(value, "length")?.value as unknown;
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0) return invalid(`${name} must have a valid length`);
  for (const key of Reflect.ownKeys(value)) {
    if (key === "length") continue;
    if (typeof key !== "string" || !/^(0|[1-9]\d*)$/u.test(key) || Number(key) >= length) return invalid(`${name} must be a dense array without extra properties`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor)) return invalid(`${name} must contain data properties, not accessors`);
  }
  const result: unknown[] = [];
  for (let i = 0; i < length; i += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
    if (descriptor === undefined || !("value" in descriptor)) return invalid(`${name} must not contain sparse entries`);
    result.push(descriptor.value);
  }
  return result;
}

function concreteOrPattern(value: unknown): value is string {
  if (value === "*") return true;
  if (typeof value !== "string" || value.length === 0 || /[\s*]/u.test(value)) {
    if (typeof value === "string" && value.endsWith(".*")) {
      const prefix = value.slice(0, -2);
      return prefix.length > 0 && !/[\s*]/u.test(prefix) && prefix.split(".").every(Boolean);
    }
    return false;
  }
  return value.split(".").every(Boolean);
}

function scope(value: unknown, name: string): Scope | undefined {
  if (value === undefined) return undefined;
  const copy = record(value, name);
  for (const [dimension, entry] of Object.entries(copy)) {
    if (dimension.length === 0 || typeof entry !== "string" || entry.length === 0) {
      return invalid(`${name} must contain non-empty string dimensions`);
    }
  }
  return copy as Scope;
}

function validity(value: Record<string, unknown>, name: string): { startsAt?: number; expiresAt?: number } {
  const startsAt = value.startsAt;
  const expiresAt = value.expiresAt;
  if (startsAt !== undefined && !Number.isSafeInteger(startsAt)) return invalid(`${name} startsAt must be a safe integer`);
  if (expiresAt !== undefined && !Number.isSafeInteger(expiresAt)) return invalid(`${name} expiresAt must be a safe integer`);
  if (typeof startsAt === "number" && typeof expiresAt === "number" && startsAt > expiresAt) {
    return invalid(`${name} validity bounds are inverted`);
  }
  return {
    ...(startsAt === undefined ? {} : { startsAt: startsAt as number }),
    ...(expiresAt === undefined ? {} : { expiresAt: expiresAt as number }),
  };
}

function fact(value: unknown, name: string): EffectiveFact {
  const item = checkedRecord(value, FACT_KEYS, name);
  if (!concreteOrPattern(item.permission)) return invalid(`${name} permission must be a supported permission pattern`);
  if (item.effect !== "grant" && item.effect !== "deny") return invalid(`${name} effect must be grant or deny`);
  const factScope = scope(item.scope, `${name} scope`);
  const bounds = validity(item, name);
  if (item.provenanceId !== undefined && typeof item.provenanceId !== "string") return invalid(`${name} provenanceId must be a string`);
  return {
    permission: item.permission,
    effect: item.effect,
    ...(factScope === undefined ? {} : { scope: factScope }),
    ...bounds,
    ...(item.provenanceId === undefined ? {} : { provenanceId: item.provenanceId as string }),
  };
}

function mergeScope(left: Scope | undefined, right: Scope | undefined): { scope?: Scope; conflict: boolean } {
  if (left === undefined) return { ...(right === undefined ? {} : { scope: right }), conflict: false };
  if (right === undefined) return { scope: left, conflict: false };
  const merged: Record<string, string> = Object.create(null);
  for (const [key, value] of Object.entries(left)) merged[key] = value;
  for (const [key, value] of Object.entries(right)) {
    if (Object.hasOwn(merged, key) && merged[key] !== value) return { conflict: true };
    merged[key] = value;
  }
  return { scope: merged, conflict: false };
}

function intersectBounds(assignment: RoleAssignment, permission: EffectiveFact): { startsAt?: number; expiresAt?: number } | undefined {
  const starts = [assignment.startsAt, permission.startsAt].filter((value): value is number => value !== undefined);
  const ends = [assignment.expiresAt, permission.expiresAt].filter((value): value is number => value !== undefined);
  const startsAt = starts.length === 0 ? undefined : Math.max(...starts);
  const expiresAt = ends.length === 0 ? undefined : Math.min(...ends);
  if (startsAt !== undefined && expiresAt !== undefined && startsAt >= expiresAt) return undefined;
  return { ...(startsAt === undefined ? {} : { startsAt }), ...(expiresAt === undefined ? {} : { expiresAt }) };
}

/** Expand role assignments into validated, evaluation-ready facts without evaluating time. */
export function expandRoles(
  roleDefinitions: readonly RoleDefinition[],
  assignments: readonly RoleAssignment[],
  directFacts: readonly EffectiveFact[] = [],
): ExpandRolesResult {
  const definitions = new Map<string, EffectiveFact[]>();
  for (const entry of array(roleDefinitions, "Role definitions")) {
    const definition = checkedRecord(entry, DEFINITION_KEYS, "Role definition");
    if (typeof definition.name !== "string" || definition.name.length === 0) return invalid("Role definition name must be a non-empty string");
    if (definitions.has(definition.name)) return invalid(`Duplicate role definition: ${definition.name}`);
    const permissions = array(definition.permissions, `Role ${definition.name} permissions`).map((permission) => fact(permission, `Role ${definition.name} permission`));
    definitions.set(definition.name, permissions);
  }

  const normalizedAssignments: RoleAssignment[] = array(assignments, "Role assignments").map((entry) => {
    const assignment = checkedRecord(entry, ASSIGNMENT_KEYS, "Role assignment");
    if (typeof assignment.roleName !== "string" || assignment.roleName.length === 0) return invalid("Role assignment roleName must be a non-empty string");
    const assignmentScope = scope(assignment.scope, "Role assignment scope");
    const bounds = validity(assignment, "Role assignment");
    if (assignment.provenanceId !== undefined && typeof assignment.provenanceId !== "string") return invalid("Role assignment provenanceId must be a string");
    return {
      roleName: assignment.roleName,
      ...(assignmentScope === undefined ? {} : { scope: assignmentScope }),
      ...bounds,
      ...(assignment.provenanceId === undefined ? {} : { provenanceId: assignment.provenanceId as string }),
    };
  });
  const normalizedDirectFacts = array(directFacts, "Direct facts").map((entry) => fact(entry, "Direct fact"));
  const facts: EffectiveFact[] = [];
  const diagnostics: NormalizationDiagnostic[] = [];
  let omittedDiagnostics = 0;
  const diagnose = (diagnostic: NormalizationDiagnostic): void => {
    if (diagnostics.length < MAX_DIAGNOSTICS) diagnostics.push(diagnostic);
    else omittedDiagnostics += 1;
  };

  for (const assignment of normalizedAssignments) {
    const permissions = definitions.get(assignment.roleName);
    if (permissions === undefined) return invalid(`Missing role definition: ${assignment.roleName}`);
    for (const permission of permissions) {
      const combinedScope = mergeScope(assignment.scope, permission.scope);
      if (combinedScope.conflict) {
        diagnose({ code: "scope-conflict", roleName: assignment.roleName, permission: permission.permission });
        continue;
      }
      const bounds = intersectBounds(assignment, permission);
      if (bounds === undefined) {
        diagnose({ code: "empty-validity", roleName: assignment.roleName, permission: permission.permission });
        continue;
      }
      facts.push({
        permission: permission.permission,
        effect: permission.effect,
        ...(combinedScope.scope === undefined ? {} : { scope: combinedScope.scope }),
        ...bounds,
        ...((permission.provenanceId ?? assignment.provenanceId) === undefined ? {} : { provenanceId: permission.provenanceId ?? assignment.provenanceId }),
      });
    }
  }
  for (const directFact of normalizedDirectFacts) facts.push(directFact);
  return { facts, diagnostics, omittedDiagnostics };
}
