/** Exact host-defined dimensions. Omission means global applicability. */
export type Scope = Readonly<Record<string, string>>;

export type EffectiveFact = {
  readonly permission: string;
  readonly effect: "grant" | "deny";
  readonly scope?: Scope;
  readonly startsAt?: number;
  readonly expiresAt?: number;
  readonly provenanceId?: string;
};

export type AuthorizationSnapshot = {
  readonly facts: readonly EffectiveFact[];
  readonly knownActions: readonly string[];
};

export type DefaultRisk = "low" | "high";
export type UnknownPermissionBehavior = "deny" | "allow-if-wildcard-granted";
export type RecognitionSettings = { readonly unknownPermissions?: UnknownPermissionBehavior };
export type ActionPolicy<Risk extends string = DefaultRisk> = RecognitionSettings & {
  readonly risk?: Risk;
};
export type AuthorizationPolicy<Risk extends string = DefaultRisk> = {
  readonly riskLevels: readonly Risk[];
  readonly defaults?: RecognitionSettings;
  readonly risk?: Readonly<Record<string, Risk>>;
  readonly byRisk?: Readonly<Partial<Record<Risk, RecognitionSettings>>>;
};

export type EvaluationInput<Risk extends string = DefaultRisk> = {
  readonly action: string;
  readonly snapshot: AuthorizationSnapshot;
  readonly at: number;
  readonly scope?: Scope;
  readonly policy?: AuthorizationPolicy<Risk>;
  readonly actionPolicy?: ActionPolicy<Risk>;
};

export type CoreDecision =
  | {
      readonly outcome: "allow";
      readonly code: "granted";
      readonly recognition: "known" | "wildcard-exception";
    }
  | {
      readonly outcome: "deny";
      readonly code: "unknown-action" | "explicit-deny" | "no-applicable-grant";
    };

/** Invalid direct input or unsupported fields, distinct from authorization refusal. */
export class AuthorizationFault extends TypeError {
  readonly code = "invalid-input" as const;

  constructor(message: string) {
    super(message);
    this.name = "AuthorizationFault";
  }
}

const INPUT_KEYS = new Set(["action", "snapshot", "at", "scope", "policy", "actionPolicy"]);
const SNAPSHOT_KEYS = new Set(["facts", "knownActions"]);
const FACT_KEYS = new Set([
  "permission",
  "effect",
  "scope",
  "startsAt",
  "expiresAt",
  "provenanceId",
]);

function invalid(message: string): never {
  throw new AuthorizationFault(message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertDataProperties(value: object, name: string): void {
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor)) {
      invalid(`${name} must contain data properties, not accessors`);
    }
  }
}

function assertKeys(value: Record<string, unknown>, allowed: Set<string>, name: string): void {
  assertDataProperties(value, name);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || !allowed.has(key)) {
      invalid(`${name} contains an unsupported field`);
    }
  }
}

function isConcreteKey(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && !/[\s*]/u.test(value)
    && value.split(".").every((part) => part.length > 0);
}

function isPattern(value: unknown): value is string {
  if (value === "*") return true;
  if (typeof value !== "string") return false;
  if (value.endsWith(".*")) return isConcreteKey(value.slice(0, -2));
  return isConcreteKey(value);
}

function copyRecord(value: unknown, name: string): Record<string, unknown> {
  if (!isRecord(value)) invalid(`${name} must be a plain data object`);
  const copy: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== "string" || descriptor === undefined || !("value" in descriptor)) {
      invalid(`${name} must contain string-keyed data properties, not accessors`);
    }
    Object.defineProperty(copy, key, { value: descriptor.value, enumerable: true });
  }
  return copy;
}

function copyArray(value: unknown, name: string): unknown[] {
  if (!Array.isArray(value)) invalid(`${name} must be an array`);
  assertDataProperties(value, name);
  const length = Object.getOwnPropertyDescriptor(value, "length")?.value as unknown;
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0) {
    invalid(`${name} must have a valid length`);
  }
  const copy: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor)) {
      invalid(`${name} must contain indexed data properties without holes`);
    }
    copy.push(descriptor.value);
  }
  return copy;
}

function normalizeScope(value: unknown, name: string): Scope | undefined {
  if (value === undefined) return undefined;
  const copy = copyRecord(value, name);
  for (const [dimension, entry] of Object.entries(copy)) {
    if (dimension.length === 0 || typeof entry !== "string" || entry.length === 0) {
      invalid(`${name} must contain non-empty string dimensions`);
    }
  }
  return copy as Scope;
}

type NormalizedPolicy = {
  readonly defaults: RecognitionSettings;
  readonly risk: Readonly<Record<string, string>>;
  readonly byRisk: Readonly<Record<string, RecognitionSettings>>;
  readonly inline?: ActionPolicy<string>;
};

const BEHAVIOR_KEYS = new Set(["unknownPermissions"]);
const POLICY_KEYS = new Set(["riskLevels", "defaults", "risk", "byRisk"]);
const ACTION_POLICY_KEYS = new Set(["risk", "unknownPermissions"]);

function normalizeBehavior(value: unknown, name: string): RecognitionSettings {
  const settings = copyRecord(value, name);
  assertKeys(settings, BEHAVIOR_KEYS, name);
  const behavior = settings.unknownPermissions;
  if (behavior === undefined) return {};
  if (behavior !== "deny" && behavior !== "allow-if-wildcard-granted") {
    invalid(`${name} has an unsupported unknownPermissions behavior`);
  }
  return { unknownPermissions: behavior };
}

function normalizePolicy(policyValue: unknown, actionPolicyValue: unknown): NormalizedPolicy | undefined {
  if (policyValue === undefined && actionPolicyValue === undefined) return undefined;
  const policy = policyValue === undefined
    ? { riskLevels: ["low", "high"] }
    : copyRecord(policyValue, "Authorization policy");
  assertKeys(policy, POLICY_KEYS, "Authorization policy");
  const levels = copyArray(policy.riskLevels, "Policy riskLevels");
  const accepted = new Set<string>();
  for (const level of levels) {
    if (typeof level !== "string" || level.length === 0 || accepted.has(level)) invalid("Policy riskLevels must contain unique non-empty labels");
    accepted.add(level);
  }
  const risk: Record<string, string> = Object.create(null);
  if (policy.risk !== undefined) {
    const rules = copyRecord(policy.risk, "Policy risk rules");
    for (const [pattern, label] of Object.entries(rules)) {
      if (!isPattern(pattern)) invalid("Policy risk rule has an invalid pattern");
      if (typeof label !== "string" || !accepted.has(label)) invalid("Policy risk rule uses an unregistered risk label");
      risk[pattern] = label;
    }
  }
  const byRisk: Record<string, RecognitionSettings> = Object.create(null);
  if (policy.byRisk !== undefined) {
    const settings = copyRecord(policy.byRisk, "Policy byRisk settings");
    for (const [label, value] of Object.entries(settings)) {
      if (!accepted.has(label)) invalid("Policy byRisk uses an unregistered risk label");
      byRisk[label] = normalizeBehavior(value, `Policy byRisk.${label}`);
    }
  }
  const inline = actionPolicyValue === undefined ? undefined : (() => {
    const action = copyRecord(actionPolicyValue, "Action policy");
    assertKeys(action, ACTION_POLICY_KEYS, "Action policy");
    if (action.risk !== undefined && (typeof action.risk !== "string" || !accepted.has(action.risk))) {
      invalid("Action policy uses an unregistered risk label");
    }
    return {
      ...normalizeBehavior({ unknownPermissions: action.unknownPermissions }, "Action policy"),
      ...(action.risk === undefined ? {} : { risk: action.risk as string }),
    };
  })();
  return {
    defaults: policy.defaults === undefined ? {} : normalizeBehavior(policy.defaults, "Policy defaults"),
    risk,
    byRisk,
    ...(inline === undefined ? {} : { inline }),
  };
}

type NormalizedInput = Omit<EvaluationInput<string>, "policy" | "actionPolicy"> & { readonly policy?: NormalizedPolicy };

function normalizeInput(input: unknown): NormalizedInput {
  const value = copyRecord(input, "Evaluation input");
  assertKeys(value, INPUT_KEYS, "Evaluation input");
  if (!isConcreteKey(value.action)) invalid("Action must be a concrete permission key");
  if (!Number.isSafeInteger(value.at)) invalid("Evaluation time must be a safe integer epoch timestamp");
  const scope = normalizeScope(value.scope, "Request scope");
  const policy = normalizePolicy(value.policy, value.actionPolicy);

  const snapshot = copyRecord(value.snapshot, "Snapshot");
  assertKeys(snapshot, SNAPSHOT_KEYS, "Snapshot");
  const knownActions = copyArray(snapshot.knownActions, "Snapshot knownActions");
  for (const action of knownActions) {
    if (!isConcreteKey(action)) invalid("Known actions must contain concrete permission keys");
  }

  const facts: EffectiveFact[] = [];
  for (const entry of copyArray(snapshot.facts, "Snapshot facts")) {
    const fact = copyRecord(entry, "Fact");
    assertKeys(fact, FACT_KEYS, "Fact");
    if (!isPattern(fact.permission)) invalid("Fact permission must be a supported permission pattern");
    if (fact.effect !== "grant" && fact.effect !== "deny") invalid("Fact effect must be grant or deny");
    const factScope = normalizeScope(fact.scope, "Fact scope");
    if (fact.startsAt !== undefined && !Number.isSafeInteger(fact.startsAt)) {
      invalid("Fact startsAt must be a safe integer epoch timestamp");
    }
    if (fact.expiresAt !== undefined && !Number.isSafeInteger(fact.expiresAt)) {
      invalid("Fact expiresAt must be a safe integer epoch timestamp");
    }
    if (typeof fact.startsAt === "number" && typeof fact.expiresAt === "number" && fact.startsAt > fact.expiresAt) {
      invalid("Fact validity bounds are inverted");
    }
    if (fact.provenanceId !== undefined && typeof fact.provenanceId !== "string") {
      invalid("Fact provenanceId must be a string");
    }
    facts.push({
      permission: fact.permission,
      effect: fact.effect,
      ...(factScope === undefined ? {} : { scope: factScope }),
      ...(fact.startsAt === undefined ? {} : { startsAt: fact.startsAt as number }),
      ...(fact.expiresAt === undefined ? {} : { expiresAt: fact.expiresAt as number }),
      ...(fact.provenanceId === undefined ? {} : { provenanceId: fact.provenanceId as string }),
    });
  }
  return {
    action: value.action,
    at: value.at as number,
    ...(scope === undefined ? {} : { scope }),
    snapshot: { knownActions: knownActions as string[], facts },
    ...(policy === undefined ? {} : { policy }),
  };
}

function specificity(pattern: string): number {
  if (pattern === "*") return 0;
  if (pattern.endsWith(".*")) return pattern.length;
  return Number.MAX_SAFE_INTEGER;
}

function matches(action: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -1);
    return action.startsWith(prefix);
  }
  return action === pattern;
}

function isInScope(factScope: Scope | undefined, requestScope: Scope | undefined): boolean {
  if (factScope === undefined) return true;
  const dimensions = Object.getOwnPropertyNames(factScope);
  if (dimensions.length === 0) return true;
  if (requestScope === undefined) return false;
  return dimensions.every((dimension) =>
    Object.prototype.hasOwnProperty.call(requestScope, dimension)
      && requestScope[dimension] === factScope[dimension]
  );
}

function isActive(fact: EffectiveFact, at: number): boolean {
  return (fact.startsAt === undefined || fact.startsAt <= at)
    && (fact.expiresAt === undefined || at < fact.expiresAt);
}

/**
 * Decide synchronously from a complete trusted snapshot at an explicit instant.
 * Unknown keys deny unless explicit policy permits an applicable wildcard grant.
 * Active denials win over grants.
 * Records must be plain or null-prototype data objects; accessors are rejected.
 * Evaluate validated local copies, never caller array methods or repeated property reads.
 * Namespace patterns match descendants, unlike the legacy matchesPermission helper.
 */
export function evaluate(input: EvaluationInput & { readonly policy?: undefined }): CoreDecision;
export function evaluate<const Levels extends readonly string[]>(
  input: Omit<EvaluationInput<Levels[number]>, "policy"> & {
    readonly policy: { readonly riskLevels: Levels }
      & Omit<AuthorizationPolicy<Levels[number]>, "riskLevels">;
  },
): CoreDecision;
export function evaluate(input: EvaluationInput<string>): CoreDecision {
  const { action, snapshot, at, scope, policy } = normalizeInput(input);
  const riskMatches = policy === undefined ? [] : Object.entries(policy.risk).filter(([pattern]) => matches(action, pattern));
  riskMatches.sort(([a], [b]) => specificity(b) - specificity(a));
  const resolvedRisk = policy?.inline?.risk ?? riskMatches[0]?.[1];
  const riskBehavior = resolvedRisk === undefined ? undefined : policy?.byRisk[resolvedRisk]?.unknownPermissions;
  const behavior = policy?.inline?.unknownPermissions ?? riskBehavior
    ?? policy?.defaults.unknownPermissions ?? "deny";
  const known = snapshot.knownActions.includes(action);
  const matching = snapshot.facts.filter((fact) =>
    matches(action, fact.permission) && isInScope(fact.scope, scope) && isActive(fact, at)
  );

  if (matching.some((fact) => fact.effect === "deny")) {
    return { outcome: "deny", code: "explicit-deny" };
  }
  if (!known) {
    const wildcardGrant = matching.some((fact) => fact.effect === "grant" && fact.permission !== action);
    if (behavior === "allow-if-wildcard-granted" && wildcardGrant) {
      return { outcome: "allow", code: "granted", recognition: "wildcard-exception" };
    }
    return { outcome: "deny", code: "unknown-action" };
  }
  if (matching.some((fact) => fact.effect === "grant")) {
    return { outcome: "allow", code: "granted", recognition: "known" };
  }
  return { outcome: "deny", code: "no-applicable-grant" };
}

/** Project a trusted evaluator result to its enforcement boolean. */
export function isAllowed(decision: CoreDecision): boolean {
  return decision.outcome === "allow";
}

/** Expose only the enforcement boolean, without internal reasons or provenance. */
export function toPublic(decision: CoreDecision): { readonly allowed: boolean } {
  return { allowed: isAllowed(decision) };
}
