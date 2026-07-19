/**
 * @mizan/core — Runtime-neutral TypeScript authorization decision layer.
 *
 * ## Design principles
 *
 * - **Runtime-neutral**: Core has no dependency on Bun, Node, an ORM, a database
 *   driver, React, Redis, or any authentication provider.
 * - **Host-agnostic**: Authentication is handled by the host. Mizan receives a
 *   trusted principal and normalized authorization facts.
 * - **Conservative defaults**: No grant means deny. A matching denial overrides
 *   a grant. Stale or unavailable sources are not silently accepted as fresh data.
 * - **Composable**: Adapters provide semantic facts; Mizan evaluates them against
 *   application-defined policy plans.
 */

// ─── Core types ────────────────────────────────────────────────────────────

/**
 * The fundamental authorization outcome.
 * - `deny` is the default when no grant exists or a matching denial is active.
 * - `allow` means the permission is granted after evaluating all applicable
 *   grants, denials, temporal constraints, scopes, and resource conditions.
 */
export type AuthorizationDecision = "allow" | "deny";

/**
 * Minimal AbortSignal interface for cancellation support.
 *
 * This mirrors the native {@link AbortSignal} available at runtime in
 * modern Node.js and Bun. We define it here rather than pulling in DOM
 * types so the core stays runtime-neutral.
 */
export interface CancellationSignal {
  readonly aborted: boolean;
  readonly reason?: unknown;
}

/**
 * Context passed to a source resolver when resolving authorization facts.
 *
 * - `principalId` — The trusted principal identifier (always present during evaluation).
 * - `now` — The evaluation timestamp, so sources can apply temporal logic or record it.
 * - `signal` — Optional {@link CancellationSignal} for cancellation support.
 */
export interface ResolveContext {
  readonly principalId: string;
  readonly now: Date;
  readonly signal?: CancellationSignal;
}

/**
 * A resolver that an adapter-backed source implements to supply
 * authorization facts to the evaluation layer.
 */
export interface SourceResolver {
  /** Resolve authorization facts for a given context. */
  resolve(context: ResolveContext): Promise<SourceOutcome>;
}

/**
 * Stable machine-readable reason codes for `deny` outcomes.
 * Each code corresponds to a specific evaluation condition so callers can
 * distinguish expected denials (e.g., no grant) from configuration errors.
 */
export type DenyReason =
  | "no-grant"
  | "matching-denial"
  | "expired"
  | "out-of-scope"
  | "guard-denied"
  | "source-unavailable"
  | "stale-not-accepted"
  | "resource-condition-failed"
  | "configuration-error"
  | "contract-violation";

/**
 * Structured result from `decide()`.
 *
 * - `reason` is populated for `deny` outcomes.
 * - `explanation` is an optional bounded trace for diagnostics. It is **not**
 *   a full dump of adapter internals, raw claims, or database rows.
 */
export interface AuthorizationResult {
  readonly decision: AuthorizationDecision;
  readonly reason: DenyReason | null;
  readonly explanation?: string;
}

/**
 * A normalized authorization fact supplied by an adapter.
 *
 * Facts represent **what the application has recorded**, not a final decision.
 * Mizan evaluates grants and denials from these facts against the requested
 * permission, temporal context, scope, and resource conditions.
 */
export interface AuthorizationFact {
  /** The permission key (e.g., "files.read", "admin.*", "*"). */
  readonly permission: string;
  /** `"grant"` = permission granted, `"deny"` = permission denied. */
  readonly effect: "grant" | "deny";
  /**
   * Optional scope. An omitted scope means global applicability.
   * Host-specific scope collections should be normalized into separate facts.
   */
  readonly scope?: string;
  /** Absolute validity start (ISO 8601). Omitted = active immediately. */
  readonly startsAt?: string;
  /** Absolute validity end (ISO 8601, exclusive). Omitted = no expiry. */
  readonly expiresAt?: string;
  /**
   * Optional recurring schedule. When present, the fact is active only when
   * both the absolute window and the recurring schedule match.
   */
  readonly schedule?: RecurringSchedule;
}

/**
 * A recurring time window, evaluated against the current time in the
 * specified IANA time zone.
 */
export interface RecurringSchedule {
  /** IANA time zone identifier (e.g., "Europe/Berlin", "America/New_York"). */
  readonly timezone: string;
  /** Weekly windows (day-of-week + time ranges). */
  readonly weeks?: WeeklyWindow[];
  /** Date-specific windows (calendar dates + time ranges). */
  readonly dates?: DateWindow[];
}

export type DayOfWeek =
  | "monday"
  | "tuesday"
  | "wednesday"
  | "thursday"
  | "friday"
  | "saturday"
  | "sunday";

export interface TimeRange {
  /** Start time as "HH:mm" in the schedule's timezone (inclusive). */
  readonly start: string;
  /** End time as "HH:mm" in the schedule's timezone (exclusive). */
  readonly end: string;
}

export interface WeeklyWindow {
  readonly day: DayOfWeek;
  /** One or more time ranges within this day. */
  readonly times: TimeRange[];
}

export interface DateWindow {
  /** Calendar date in "YYYY-MM-DD" format. */
  readonly date: string;
  /** One or more time ranges within this date. */
  readonly times: TimeRange[];
}

/**
 * A role definition — a named set of permission facts.
 */
export interface RoleDefinition {
  readonly name: string;
  readonly permissions: AuthorizationFact[];
}

/**
 * A role assignment linking a principal to a role.
 */
export interface RoleAssignment {
  readonly principalId: string;
  readonly roleName: string;
  readonly startsAt?: string;
  readonly expiresAt?: string;
}

/**
 * A guard precondition, evaluated before permission facts.
 *
 * Guards represent **external conditions** (e.g., session not revoked,
 * account not suspended). A required guard that fails short-circuits all
 * permission checks in the request.
 */
export interface GuardResult {
  readonly pass: boolean;
  readonly reason?: string;
}

// ─── Source outcomes ───────────────────────────────────────────────────────

/**
 * Semantic outcome of a named source when asked for authorization facts.
 *
 * - `facts` — the source returned data (possibly empty, which is
 *   semantically meaningful).
 * - `miss` — the source has no coverage for this context.
 * - `unavailable` — the source could not be reached.
 */
export type SourceStatus = "facts" | "miss" | "unavailable";

export interface SourceOutcome {
  readonly status: SourceStatus;
  readonly facts: AuthorizationFact[];
  readonly freshness?: "fresh" | "stale" | "unknown";
}

// ─── Plan types ────────────────────────────────────────────────────────────

/**
 * How a named source plan should handle source unavailability.
 */
export type UnavailablePolicy = "fail-closed" | "fail-open" | "fallback";

export interface SourcePlanEntry {
  readonly sourceName: string;
  readonly required: boolean;
  readonly onUnavailable?: UnavailablePolicy;
}

export type CompositionStrategy = "fallback" | "merge" | "authoritative";

export interface SourcePlan {
  readonly name: string;
  readonly strategy: CompositionStrategy;
  readonly sources: SourcePlanEntry[];
}

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Create a Mizan authorization instance.
 *
 * @returns An authorization handle.
 */
export function createMizan(): Mizan {
  return new Mizan();
}

// ─── Source registry ───────────────────────────────────────────────────────

/**
 * A collection of registered sources used internally by Mizan.
 */
class SourceRegistry {
  readonly sources = new Map<string, SourceResolver>();

  register(name: string, resolver: SourceResolver): void {
    if (this.sources.has(name)) {
      throw new Error(
        `Source "${name}" is already registered. Use a different name or remove the existing source first.`,
      );
    }
    this.sources.set(name, resolver);
  }

  getAll(): Map<string, SourceResolver> {
    return this.sources;
  }

  get(name: string): SourceResolver | undefined {
    return this.sources.get(name);
  }

  has(name: string): boolean {
    return this.sources.has(name);
  }
}

// ─── Plan registry ─────────────────────────────────────────────────────────

/**
 * A collection of registered plans used internally by Mizan.
 */
class PlanRegistry {
  readonly plans = new Map<string, SourcePlan>();

  register(name: string, plan: SourcePlan): void {
    if (this.plans.has(name)) {
      throw new Error(
        `Plan "${name}" is already registered. Use a different name or remove the existing plan first.`,
      );
    }
    this.plans.set(name, plan);
  }

  get(name: string): SourcePlan | undefined {
    return this.plans.get(name);
  }
}

// ─── Evaluation ────────────────────────────────────────────────────────────

/**
 * Collect facts from sources, optionally filtered to a named plan.
 *
 * When a `planName` is provided, only the sources referenced by that plan
 * are resolved. Otherwise all registered sources are resolved.
 */
async function collectFacts(
  sources: Map<string, SourceResolver>,
  plans: Map<string, SourcePlan>,
  principalId: string,
  planName?: string,
): Promise<AuthorizationFact[]> {
  let targetSources: Map<string, SourceResolver>;

  if (planName !== undefined) {
    const plan = plans.get(planName);
    if (!plan) {
      throw new Error(
        `Plan "${planName}" not found. Register the plan via registerPlan() before using it.`,
      );
    }

    targetSources = new Map();
    for (const entry of plan.sources) {
      const resolver = sources.get(entry.sourceName);
      if (!resolver) {
        throw new Error(
          `Source "${entry.sourceName}" referenced by plan "${planName}" was not found. Register the source before using the plan.`,
        );
      }
      targetSources.set(entry.sourceName, resolver);
    }
  } else {
    targetSources = new Map(sources);
  }

  const now = new Date();
  const allFacts: AuthorizationFact[] = [];

  for (const [name, resolver] of targetSources) {
    let outcome: SourceOutcome;
    try {
      outcome = await resolver.resolve({ principalId, now });
    } catch (e) {
      throw new Error(
        `Source "${name}" threw during resolve: ${e instanceof Error ? e.message : String(e)}`,
      );
    }

    if (outcome === null || outcome === undefined) {
      throw new TypeError(
        `Contract violation: source "${name}" returned null or undefined outcome`,
      );
    }

    if (outcome.status !== "facts" && outcome.status !== "miss" && outcome.status !== "unavailable") {
      throw new TypeError(
        `Contract violation: source "${name}" returned unknown status "${outcome.status}"`,
      );
    }

    if (!Array.isArray(outcome.facts)) {
      throw new TypeError(
        `Contract violation: source "${name}" returned non-array facts`,
      );
    }

    if (outcome.status === "unavailable") {
      throw new Error(
        `Source "${name}" is unavailable. An unavailable source is treated as a contract violation — ensure the source is reachable or remove it from the plan.`,
      );
    }

    if (outcome.status === "facts") {
      for (const fact of outcome.facts) {
        if (fact === null || fact === undefined) {
          throw new TypeError(
            `Contract violation: source "${name}" returned a null or undefined fact entry`,
          );
        }
        if (typeof fact.permission !== "string" || fact.permission.length === 0) {
          throw new TypeError(
            `Contract violation: source "${name}" returned a fact with a missing or non-string permission`,
          );
        }
        if (fact.effect !== "grant" && fact.effect !== "deny") {
          throw new TypeError(
            `Contract violation: source "${name}" returned a fact with an unsupported effect "${fact.effect}"`,
          );
        }
        allFacts.push(fact);
      }
    }
  }

  return allFacts;
}

/**
 * Evaluate all facts against a single permission and return the decision.
 *
 * v0.1 logic (simplified):
 * 1. Filter to exact-matching facts.
 * 2. If any matching denial exists → deny (matching-denial).
 * 3. If any matching grant exists → allow.
 * 4. Otherwise → deny (no-grant).
 */
function evaluate(
  facts: AuthorizationFact[],
  permission: string,
): AuthorizationResult {
  const matching = facts.filter((f) => f.permission === permission);

  const hasDenial = matching.some((f) => f.effect === "deny");
  if (hasDenial) {
    return { decision: "deny", reason: "matching-denial" };
  }

  const hasGrant = matching.some((f) => f.effect === "grant");
  if (hasGrant) {
    return { decision: "allow", reason: null };
  }

  return { decision: "deny", reason: "no-grant" };
}

// ─── PrincipalEvaluator ────────────────────────────────────────────────────

/**
 * A principal-bound authorization evaluator created by
 * {@link Mizan.forPrincipal}.
 *
 * Provides `can()` for boolean checks and `decide()` for structured
 * authorization results.
 */
export class PrincipalEvaluator {
  /** @internal */
  constructor(
    private readonly sources: Map<string, SourceResolver>,
    private readonly plans: Map<string, SourcePlan>,
    readonly principalId: string,
    private readonly planName?: string,
  ) {}

  /**
   * Check whether this principal has a permission.
   *
   * @returns `true` if the permission is granted, `false` otherwise.
   */
  async can(permission: string): Promise<boolean> {
    const result = await this.decide(permission);
    return result.decision === "allow";
  }

  /**
   * Check a permission and return a structured result.
   *
   * Unlike `can`, `decide` returns a full `AuthorizationResult` with
   * a stable reason code, suitable for auditing and diagnostics.
   */
  async decide(permission: string): Promise<AuthorizationResult> {
    if (this.sources.size === 0) {
      throw new Error(
        "No sources registered on the Mizan instance. Register at least one source via registerSource() or useMemoryAdapter() before calling can/decide.",
      );
    }

    const facts = await collectFacts(this.sources, this.plans, this.principalId, this.planName);
    return evaluate(facts, permission);
  }
}

// ─── Mizan instance ────────────────────────────────────────────────────────

/**
 * Authorization handle created by `createMizan`.
 *
 * This is the public entry point for all authorization operations.
 * The class shape is intentionally minimal in v0.1 — extensions
 * (resource-aware checks, guards, plans, management) are added through
 * explicit seams without changing the base API.
 */
export class Mizan {
  private readonly registry = new SourceRegistry();
  private readonly planRegistry = new PlanRegistry();

  /**
   * Register a named source resolver.
   *
   * @param name - A unique name for this source.
   * @param resolver - The resolver that returns authorization facts.
   */
  registerSource(name: string, resolver: SourceResolver): void {
    this.registry.register(name, resolver);
  }

  /**
   * Register a named source plan.
   *
   * Plans define which sources are resolved during evaluation. When a plan
   * name is provided to {@link forPrincipal}, only the sources referenced
   * by that plan are consulted.
   *
   * @param name - A unique name for this plan.
   * @param plan - The plan definition with source references.
   */
  registerPlan(name: string, plan: SourcePlan): void {
    this.planRegistry.register(name, plan);
  }

  /**
   * Create a principal-bound authorization evaluator.
   *
   * The returned {@link PrincipalEvaluator} evaluates permissions for
   * the given principal. When a `planName` is provided, only the sources
   * referenced by that plan are resolved. Otherwise all registered sources
   * are consulted.
   *
   * @param principalId - The trusted principal identifier.
   * @param planName - Optional plan name for scoped evaluation.
   * @returns A principal-bound evaluator.
   */
  forPrincipal(principalId: string, planName?: string): PrincipalEvaluator {
    return new PrincipalEvaluator(
      this.registry.getAll(),
      this.planRegistry.plans,
      principalId,
      planName,
    );
  }
}

/**
 * Check whether a principal has a permission.
 *
 * This standalone convenience function uses a default Mizan instance.
 * Prefer creating a `Mizan` instance and calling `mizan.forPrincipal(id).can(perm)`
 * when you need to configure sources.
 *
 * @returns `true` if the permission is granted, `false` otherwise.
 */
export async function can(
  _permission: string,
  _options?: { principalId?: string },
): Promise<boolean> {
  // Standalone convenience — always denies by default since no sources exist.
  return false;
}

/**
 * Check a permission and return a structured result.
 *
 * This standalone convenience function uses a default Mizan instance.
 * Prefer creating a `Mizan` instance and calling `mizan.forPrincipal(id).decide(perm)`
 * when you need to configure sources.
 *
 * Unlike `can`, `decide` returns a full `AuthorizationResult` with
 * a stable reason code, suitable for auditing and diagnostics.
 */
export async function decide(
  _permission: string,
  _options?: { principalId?: string },
): Promise<AuthorizationResult> {
  // Standalone convenience — always denies by default since no sources exist.
  return {
    decision: "deny",
    reason: "no-grant",
    explanation: "Not yet implemented — use mizan.forPrincipal(id).decide(perm) for a configured instance.",
  };
}
