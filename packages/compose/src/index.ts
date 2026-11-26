import {
  evaluate,
  type ActionPolicy,
  type AuthorizationPolicy,
  type AuthorizationSnapshot,
  type CoreDecision,
  type Scope,
} from "@mizan/core";

export class AuthorizationFault extends TypeError {
  readonly code = "invalid-input" as const;
  constructor(message: string) {
    super(message);
    this.name = "AuthorizationFault";
  }
}

export type Awaitable<T> = T | PromiseLike<T>;
export type Binding = {
  readonly subjectId: string;
  readonly partitionKey: string;
  readonly action: string;
  readonly scope: Scope;
};
export type ContextBinding = Pick<Binding, "subjectId" | "partitionKey" | "scope">;
export type CancellationSignal = { readonly aborted: boolean; readonly reason?: unknown };
export type SourceQuery<Context> = Binding & {
  readonly context: Context;
  readonly startedAt: number;
  readonly signal?: CancellationSignal;
};
export type Acceptance = {
  readonly consistency: "snapshot" | "current";
  readonly maxAgeMs: number;
};
export type SourceOutcome =
  | { readonly status: "miss" }
  | { readonly status: "unavailable"; readonly code: string }
  | {
      readonly status: "complete";
      readonly binding: Binding;
      readonly contribution: string;
      readonly recognitionDomains: readonly string[];
      readonly snapshot: AuthorizationSnapshot;
      readonly assurance: {
        readonly consistency: "snapshot" | "current";
        readonly dataAsOf: number;
        readonly revision?: string;
      };
    };
export type Source<Context> = {
  readonly contribution: string;
  readonly recognitionDomains: readonly string[];
  readonly resolve: (query: SourceQuery<Context>) => Awaitable<SourceOutcome>;
};
export type Receipt = {
  readonly evidence: Extract<SourceOutcome, { status: "complete" }>;
  readonly requirements: Acceptance;
};
export type PlanResolution =
  | { readonly status: "complete"; readonly selected: readonly Receipt[] }
  | { readonly status: "miss" }
  | { readonly status: "unavailable"; readonly code: string }
  | { readonly status: "unacceptable"; readonly code: "assurance-unmet" };
export type EvidencePlan<Context> = {
  readonly contributions: readonly string[];
  readonly recognitionDomains: readonly string[];
  readonly resolve: (query: SourceQuery<Context>) => Awaitable<PlanResolution>;
};
export type IndeterminateCode = "evidence-unavailable" | "evidence-incomplete" | "assurance-unmet" | "cancelled";
export type Decision = CoreDecision
  | { readonly outcome: "deny"; readonly code: "unrouted-action" }
  | { readonly outcome: "indeterminate"; readonly code: IndeterminateCode };
export type ActionDefinition<Context, Risk extends string> = {
  readonly source: EvidencePlan<Context>;
  readonly recognitionRequirements: readonly string[];
  readonly policy?: ActionPolicy<Risk>;
};
export type RouteDefinition<Context, Risk extends string> = ActionDefinition<Context, Risk>;
type ActionCalls<Actions> = keyof Actions & string;
type RequestAuthorizer<Actions extends Record<string, unknown>> = {
  readonly can: (action: ActionCalls<Actions>) => Promise<boolean>;
  readonly decide: (action: ActionCalls<Actions>) => Promise<Decision>;
  readonly decideDynamic: (input: { readonly action: string }) => Promise<Decision>;
};
type Authorizer<Context, Actions extends Record<string, unknown>> = {
  readonly forContext: (context: Context, options?: { readonly signal?: CancellationSignal }) => RequestAuthorizer<Actions>;
};
type RiskRegistration<Levels extends readonly string[]> = { readonly riskLevels: Levels } & Omit<AuthorizationPolicy<Levels[number]>, "riskLevels">;
type ActionConfig<Context, Risk extends string> = ActionDefinition<Context, Risk>;

function fault(message: string): never {
  throw new AuthorizationFault(message);
}
function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function assertKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || !allowed.includes(key)) fault(`${label} contains an unsupported field`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) fault(`${label} cannot contain accessors`);
  }
}
function recordCopy(value: unknown, allowed: readonly string[], label: string): Record<string, unknown> {
  if (!isRecord(value)) fault(`${label} must be a plain data object`);
  assertKeys(value, allowed, label);
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Object.keys(value)) result[key] = value[key];
  return result;
}
function cloneData(value: unknown, label: string): unknown {
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) fault(`${label} must use a plain array`);
    const length = value.length;
    const copy: unknown[] = [];
    for (const key of Reflect.ownKeys(value)) {
      if (key !== "length" && (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key) || Number(key) >= length)) {
        fault(`${label} contains unsupported array properties`);
      }
    }
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !("value" in descriptor)) fault(`${label} cannot contain holes or accessors`);
      copy.push(cloneData(descriptor.value, label));
    }
    return copy;
  }
  if (isRecord(value)) {
    const copy: Record<string, unknown> = Object.create(null);
    for (const key of Reflect.ownKeys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (typeof key !== "string" || !descriptor || !("value" in descriptor)) fault(`${label} must contain plain data properties`);
      copy[key] = cloneData(descriptor.value, label);
    }
    return copy;
  }
  if (value === null || ["string", "number", "boolean", "undefined"].includes(typeof value)) return value;
  fault(`${label} must contain only data values`);
}
function stringArray(value: unknown, label: string, unique = true): string[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) fault(`${label} must be a plain array`);
  const copy: string[] = [];
  const length = value.length;
  for (const key of Reflect.ownKeys(value)) {
    if (key !== "length" && (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key) || Number(key) >= length)) {
      fault(`${label} contains unsupported array properties`);
    }
  }
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor)) fault(`${label} cannot contain holes or accessors`);
    const entry: unknown = descriptor.value;
    if (typeof entry !== "string" || entry.length === 0) fault(`${label} must contain non-empty strings`);
    if (unique && copy.includes(entry)) fault(`${label} cannot contain duplicates`);
    copy.push(entry);
  }
  return copy;
}
function copyScope(value: unknown, label: string): Scope {
  if (!isRecord(value)) fault(`${label} must be a plain object`);
  const copy: Record<string, string> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== "string" || !descriptor || !("value" in descriptor)
      || key.length === 0 || typeof descriptor.value !== "string" || descriptor.value.length === 0) {
      fault(`${label} must contain non-empty string dimensions`);
    }
    copy[key] = descriptor.value;
  }
  return copy;
}
function copyBinding(value: unknown, label: string): ContextBinding {
  const record = recordCopy(value, ["subjectId", "partitionKey", "scope"], label);
  if (typeof record.subjectId !== "string" || record.subjectId.length === 0
    || typeof record.partitionKey !== "string" || record.partitionKey.length === 0) {
    fault(`${label} requires subjectId and partitionKey`);
  }
  return { subjectId: record.subjectId, partitionKey: record.partitionKey, scope: copyScope(record.scope, `${label}.scope`) };
}
function sameScope(left: Scope, right: Scope): boolean {
  const leftKeys = Reflect.ownKeys(left);
  const rightKeys = Reflect.ownKeys(right);
  return leftKeys.length === rightKeys.length && leftKeys.every((key) =>
    typeof key === "string" && Object.prototype.hasOwnProperty.call(right, key) && left[key] === right[key]
  );
}
function sameBinding(expected: Binding, actual: Binding): boolean {
  return expected.subjectId === actual.subjectId
    && expected.partitionKey === actual.partitionKey
    && expected.action === actual.action
    && sameScope(expected.scope, actual.scope);
}
function copyAcceptance(value: unknown): Acceptance {
  const record = recordCopy(value, ["consistency", "maxAgeMs"], "Acceptance requirements");
  if ((record.consistency !== "snapshot" && record.consistency !== "current")
    || typeof record.maxAgeMs !== "number" || !Number.isSafeInteger(record.maxAgeMs) || record.maxAgeMs < 0) {
    fault("Acceptance requirements need a supported consistency and non-negative safe maxAgeMs");
  }
  return { consistency: record.consistency, maxAgeMs: record.maxAgeMs };
}
function copyDomains(value: unknown, label: string): string[] {
  return stringArray(value, label);
}
function validatePlanResolution(value: unknown, plan: EvidencePlan<unknown>, query: SourceQuery<unknown>): PlanResolution {
  if (!isRecord(value)) fault("Evidence plan returned a malformed result");
  if (value.status === "miss") {
    assertKeys(value, ["status"], "Miss result");
    return { status: "miss" };
  }
  if (value.status === "unavailable") {
    const result = recordCopy(value, ["status", "code"], "Unavailable result");
    if (typeof result.code !== "string" || result.code.length === 0) fault("Unavailable result requires a code");
    return { status: "unavailable", code: result.code };
  }
  if (value.status === "unacceptable") {
    const result = recordCopy(value, ["status", "code"], "Unacceptable result");
    if (result.code !== "assurance-unmet") fault("Unacceptable result has an unsupported code");
    return { status: "unacceptable", code: "assurance-unmet" };
  }
  if (value.status !== "complete") fault("Evidence plan returned an unknown status");
  const result = recordCopy(value, ["status", "selected"], "Complete plan result");
  const selected = cloneData(result.selected, "Selected evidence receipts");
  if (!Array.isArray(selected) || selected.length !== 1) fault("One-source plan must return exactly one selected receipt");
  const receipt = recordCopy(selected[0], ["evidence", "requirements"], "Evidence receipt");
  const evidence = receipt.evidence as SourceOutcome;
  if (!evidence || typeof evidence !== "object" || evidence.status !== "complete") fault("Evidence receipt is not complete evidence");
  const checked = validateCompleteOutcome(evidence, {
    contribution: plan.contributions[0]!,
    recognitionDomains: plan.recognitionDomains,
  });
  if (!sameBinding(query, checked.binding)) fault("Evidence plan returned evidence for a different binding");
  const requirements = copyAcceptance(receipt.requirements);
  if (!plan.contributions.includes(checked.contribution)) fault("Evidence plan returned an undeclared contribution");
  return { status: "complete", selected: [{ evidence: checked, requirements }] };
}
function validateCompleteOutcome(value: unknown, source: Pick<Source<unknown>, "contribution" | "recognitionDomains">): Extract<SourceOutcome, { status: "complete" }> {
  const record = recordCopy(value, ["status", "binding", "contribution", "recognitionDomains", "snapshot", "assurance"], "Source outcome");
  if (record.status !== "complete") fault("Source outcome is not complete");
  const bindingRecord = recordCopy(record.binding, ["subjectId", "partitionKey", "action", "scope"], "Source binding");
  const base = copyBinding({ subjectId: bindingRecord.subjectId, partitionKey: bindingRecord.partitionKey, scope: bindingRecord.scope }, "Source binding");
  if (typeof bindingRecord.action !== "string" || bindingRecord.action.length === 0) fault("Source binding requires an action");
  if (record.contribution !== source.contribution) fault("Source contribution does not match its declaration");
  const domains = copyDomains(record.recognitionDomains, "Source recognitionDomains");
  const expected = [...source.recognitionDomains];
  if (domains.length !== expected.length || domains.some((domain, index) => domain !== expected[index])) {
    fault("Source recognitionDomains do not match their declaration");
  }
  const snapshot = recordCopy(record.snapshot, ["facts", "knownActions"], "Source snapshot");
  if (!Array.isArray(snapshot.facts) || !Array.isArray(snapshot.knownActions)) fault("Source snapshot needs facts and knownActions arrays");
  const assurance = recordCopy(record.assurance, ["consistency", "dataAsOf", "revision"], "Source assurance");
  if ((assurance.consistency !== "snapshot" && assurance.consistency !== "current")
    || typeof assurance.dataAsOf !== "number" || !Number.isSafeInteger(assurance.dataAsOf)
    || (assurance.revision !== undefined && typeof assurance.revision !== "string")) {
    fault("Source assurance is malformed");
  }
  return {
    status: "complete",
    binding: { ...base, action: bindingRecord.action },
    contribution: record.contribution,
    recognitionDomains: domains,
    snapshot: { facts: snapshot.facts as AuthorizationSnapshot["facts"], knownActions: snapshot.knownActions as string[] },
    assurance: {
      consistency: assurance.consistency,
      dataAsOf: assurance.dataAsOf,
      ...(assurance.revision === undefined ? {} : { revision: assurance.revision }),
    },
  };
}
function accepted(evidence: Extract<SourceOutcome, { status: "complete" }>, requirements: Acceptance, at: number): boolean {
  const { consistency, dataAsOf } = evidence.assurance;
  const age = at - dataAsOf;
  return (requirements.consistency === "snapshot" || consistency === "current")
    && age >= 0 && age <= requirements.maxAgeMs;
}
function isConcreteAction(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && !/[\s*]/u.test(value)
    && value.split(".").every((segment) => segment.length > 0);
}
function isRoutePattern(value: string): boolean {
  return value === "*" || (value.endsWith(".*") && isConcreteAction(value.slice(0, -2)));
}
function patternMatches(action: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith(".*")) return action.startsWith(pattern.slice(0, -1));
  return action === pattern;
}
function routeSpecificity(pattern: string): number {
  return pattern === "*" ? 0 : pattern.length;
}
function copySnapshot(snapshot: AuthorizationSnapshot, knownActions: readonly string[]): AuthorizationSnapshot {
  const copiedKnown = cloneData(snapshot.knownActions, "Source knownActions");
  const copiedFacts = cloneData(snapshot.facts, "Source facts");
  if (!Array.isArray(copiedKnown) || !Array.isArray(copiedFacts)) fault("Source snapshot needs arrays");
  return {
    knownActions: [...copiedKnown as string[], ...knownActions],
    facts: copiedFacts as AuthorizationSnapshot["facts"],
  };
}

export function accept<Context>(source: Source<Context>, requirements: Acceptance): EvidencePlan<Context> {
  const config = recordCopy(source, ["contribution", "recognitionDomains", "resolve"], "Source");
  if (typeof config.contribution !== "string" || config.contribution.length === 0 || typeof config.resolve !== "function") {
    fault("Source needs a contribution name and resolve function");
  }
  const contribution = config.contribution;
  const resolver = config.resolve as Source<Context>["resolve"];
  const domains = copyDomains(config.recognitionDomains, "Source recognitionDomains");
  const acceptance = copyAcceptance(requirements);
  return {
    contributions: [contribution],
    recognitionDomains: domains,
    resolve: async (query) => {
      const outcome: unknown = await resolver(query);
      if (!isRecord(outcome)) fault("Source returned a malformed outcome");
      if (outcome.status === "miss") {
        assertKeys(outcome, ["status"], "Miss outcome");
        return { status: "miss" };
      }
      if (outcome.status === "unavailable") {
        const result = recordCopy(outcome, ["status", "code"], "Unavailable outcome");
        if (typeof result.code !== "string" || result.code.length === 0) fault("Unavailable outcome requires a code");
        return { status: "unavailable", code: result.code };
      }
      if (outcome.status !== "complete") fault("Source returned an unknown outcome status");
      const evidence = validateCompleteOutcome(outcome, { contribution, recognitionDomains: domains });
      if (!sameBinding(query, evidence.binding)) fault("Source returned evidence for a different binding");
      if (!accepted(evidence, acceptance, query.startedAt)) return { status: "unacceptable", code: "assurance-unmet" };
      return { status: "complete", selected: [{ evidence, requirements: acceptance }] };
    },
  };
}

export function createAuthorizer<
  Context,
  const Levels extends readonly string[],
  const Actions extends Record<string, ActionConfig<Context, Levels[number]>>,
  const Routes extends Record<string, ActionConfig<Context, Levels[number]>> = {},
>(config: {
  readonly policy: RiskRegistration<Levels>;
  readonly bindContext: (context: Context) => ContextBinding;
  readonly actions: Actions;
  readonly routes?: Routes;
  readonly clock?: () => number;
}): Authorizer<Context, Actions> {
  const root = recordCopy(config, ["policy", "bindContext", "actions", "routes", "clock"], "Authorizer configuration");
  if (typeof root.bindContext !== "function") fault("bindContext must be a function");
  const bindContext = root.bindContext as (context: Context) => ContextBinding;
  const policy = root.policy;
  if (!isRecord(policy)) fault("Authorizer policy must be an object");
  const policyRecord = recordCopy(policy, ["riskLevels", "defaults", "risk", "byRisk"], "Authorizer policy");
  const policyCopy = cloneData(policyRecord, "Authorizer policy") as Record<string, unknown>;
  const levels = stringArray(policyCopy.riskLevels, "Policy riskLevels");
  if (levels.length === 0) fault("Policy riskLevels cannot be empty");
  if (!isRecord(root.actions)) fault("Authorizer actions must be an object");
  const actions = recordCopy(root.actions, Object.keys(root.actions), "Authorizer actions");
  if (root.routes !== undefined && !isRecord(root.routes)) fault("Authorizer routes must be an object");
  const routes = root.routes === undefined ? {} : recordCopy(root.routes, Object.keys(root.routes), "Authorizer routes");
  if (Object.keys(actions).length === 0 && Object.keys(routes).length === 0) fault("Authorizer requires at least one action or route");
  const clock = root.clock ?? Date.now;
  if (typeof clock !== "function") fault("Authorizer clock must be a function");

  const validateDefinition = (key: string, value: unknown, isRoute: boolean): ActionConfig<Context, Levels[number]> => {
    if (isRoute ? !isRoutePattern(key) : !isConcreteAction(key)) fault("Action or route key is malformed");
    const definition = recordCopy(value, ["source", "recognitionRequirements", "policy"], "Action definition");
    const sourcePlan = recordCopy(definition.source, ["contributions", "recognitionDomains", "resolve"], "Evidence plan");
    if (typeof sourcePlan.resolve !== "function") fault("Action source must be an evidence plan");
    const resolvePlan = sourcePlan.resolve as EvidencePlan<Context>["resolve"];
    const requirements = stringArray(definition.recognitionRequirements, "recognitionRequirements");
    const contributions = stringArray(sourcePlan.contributions, "Evidence plan contributions");
    if (contributions.length !== 1) fault("Issue 60 supports exactly one evidence contribution");
    const planDomains = stringArray(sourcePlan.recognitionDomains, "Evidence plan recognitionDomains");
    const isolatedPlan: EvidencePlan<Context> = {
      contributions: [...contributions],
      recognitionDomains: [...planDomains],
      resolve: resolvePlan,
    };
    if (requirements.some((domain) => !planDomains.includes(domain))) fault("Evidence plan does not cover required recognition domains");
    if (definition.policy !== undefined) {
      const actionPolicy = recordCopy(definition.policy, ["risk", "unknownPermissions"], "Action policy");
      if (actionPolicy.risk !== undefined && (typeof actionPolicy.risk !== "string" || !levels.includes(actionPolicy.risk))) {
        fault("Action policy risk is not registered by policy.riskLevels");
      }
      if (actionPolicy.unknownPermissions !== undefined
        && actionPolicy.unknownPermissions !== "deny" && actionPolicy.unknownPermissions !== "allow-if-wildcard-granted") {
        fault("Action policy has an unsupported unknownPermissions behavior");
      }
    }
    const isolated = {
      source: isolatedPlan,
      recognitionRequirements: [...requirements],
      ...(definition.policy === undefined ? {} : { policy: cloneData(definition.policy, "Action policy") }),
    };
    return isolated as unknown as ActionConfig<Context, Levels[number]>;
  };
  const checkedActions = new Map<string, ActionConfig<Context, Levels[number]>>();
  for (const [key, value] of Object.entries(actions)) checkedActions.set(key, validateDefinition(key, value, false));
  const checkedRoutes = new Map<string, ActionConfig<Context, Levels[number]>>();
  for (const [key, value] of Object.entries(routes)) checkedRoutes.set(key, validateDefinition(key, value, true));
  const policyProbe = {
    action: "mizan.compose.validation",
    at: 0,
    snapshot: { facts: [], knownActions: [] },
    policy: policyCopy,
  };
  try {
    evaluate(policyProbe as never);
    for (const [key, definition] of [...checkedActions, ...checkedRoutes]) {
      evaluate({
        ...policyProbe,
        action: isConcreteAction(key) ? key : "mizan.compose.validation",
        ...(definition.policy === undefined ? {} : { actionPolicy: definition.policy }),
      } as never);
    }
  } catch (error) {
    fault(`Authorizer policy is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }

  return {
    forContext(context: Context, options = {}) {
      const opts = recordCopy(options, ["signal"], "forContext options");
      const signal = opts.signal as CancellationSignal | undefined;
      if (signal !== undefined && (typeof signal !== "object" || signal === null || typeof signal.aborted !== "boolean")) {
        fault("Cancellation signal is malformed");
      }
      const boundContext = context;
      const base = copyBinding(bindContext(boundContext), "Context binding");
      const run = async (action: string): Promise<Decision> => {
        if (!isConcreteAction(action)) fault("Action must be a concrete key");
        const exact = checkedActions.get(action);
        const selectedRoute = exact ? undefined : [...checkedRoutes.keys()]
          .filter((pattern) => patternMatches(action, pattern))
          .sort((left, right) => routeSpecificity(right) - routeSpecificity(left))[0];
        const definition = exact ?? (selectedRoute === undefined ? undefined : checkedRoutes.get(selectedRoute));
        if (!definition) return { outcome: "deny", code: "unrouted-action" } as Decision;
        const now = clock();
        if (!Number.isSafeInteger(now)) fault("Authorizer clock must return safe integer epoch milliseconds");
        const query: SourceQuery<Context> = {
          ...base,
          action,
          context: boundContext,
          startedAt: now,
          ...(signal === undefined ? {} : { signal }),
        };
        if (signal?.aborted) return { outcome: "indeterminate", code: "cancelled" };
        let raw: unknown;
        try {
          raw = await definition.source.resolve(query);
        } catch (error) {
          if (signal?.aborted) return { outcome: "indeterminate", code: "cancelled" };
          throw error;
        }
        if (signal?.aborted) return { outcome: "indeterminate", code: "cancelled" };
        const result = validatePlanResolution(raw, definition.source as EvidencePlan<unknown>, query as SourceQuery<unknown>);
        if (result.status === "miss") return { outcome: "indeterminate", code: "evidence-incomplete" };
        if (result.status === "unavailable") return { outcome: "indeterminate", code: "evidence-unavailable" };
        if (result.status === "unacceptable") return { outcome: "indeterminate", code: result.code };
        const receipt = result.selected[0]!;
        const at = clock();
        if (!Number.isSafeInteger(at)) fault("Authorizer clock must return safe integer epoch milliseconds");
        if (!accepted(receipt.evidence, receipt.requirements, at)) return { outcome: "indeterminate", code: "assurance-unmet" };
        const snapshot = copySnapshot(receipt.evidence.snapshot, exact ? [action] : []);
        return evaluate({
          action,
          snapshot,
          at,
          scope: base.scope,
          policy: policyCopy as never,
          ...(definition.policy === undefined ? {} : { actionPolicy: definition.policy }),
        } as never);
      };
      return {
        can: async (action: ActionCalls<Actions>) => (await run(action)).outcome === "allow",
        decide: (action: ActionCalls<Actions>) => run(action),
        decideDynamic: (input: { readonly action: string }) => {
          const dynamic = recordCopy(input, ["action"], "Dynamic decision input");
          if (!isConcreteAction(dynamic.action)) fault("Dynamic action must be a concrete key");
          return run(dynamic.action);
        },
      };
    },
  } as Authorizer<Context, Actions>;
}
