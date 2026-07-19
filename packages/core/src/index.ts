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
 *
 * Cancellation is **not yet wired end-to-end** in v0.1. The type is
 * reserved for a follow-up so source resolvers can opt in when the
 * pipeline supports it. Callers currently cannot supply a signal.
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
 *   Cancellation is reserved for a follow-up; callers cannot supply a signal in v0.1.
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
  | "not-yet-active"
  | "outside-schedule"
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
 *
 * At least one of `weeks` or `dates` must be provided. An empty array
 * for both means no active time windows.
 */
export type RecurringSchedule = {
  /** IANA time zone identifier (e.g., "Europe/Berlin", "America/New_York"). */
  readonly timezone: string;
  /** Weekly windows (day-of-week + time ranges). */
  readonly weeks: WeeklyWindow[];
  /** Date-specific windows (calendar dates + time ranges). */
  readonly dates?: DateWindow[];
} | {
  /** IANA time zone identifier (e.g., "Europe/Berlin", "America/New_York"). */
  readonly timezone: string;
  /** Weekly windows (day-of-week + time ranges). */
  readonly weeks?: WeeklyWindow[];
  /** Date-specific windows (calendar dates + time ranges). */
  readonly dates: DateWindow[];
};

/** Ordered list of days for computing next-day overnight windows. */
const DAYS: DayOfWeek[] = [
  "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
];

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

/**
 * Optional parameters for `can()` and `decide()`.
 */
export interface EvaluateOptions {
  /**
   * Requested scope. Omitted means only unscoped (global) facts apply.
   */
  readonly scope?: string;
  /**
   * Evaluation timestamp. Defaults to current time when omitted.
   */
  readonly at?: Date;
}

export type CompositionStrategy = "fallback" | "merge" | "authoritative";

export interface SourcePlan {
  readonly name: string;
  readonly strategy: CompositionStrategy;
  readonly sources: SourcePlanEntry[];
}

// ─── Permission pattern matching ────────────────────────────────────────────

/**
 * Check whether a permission key matches a pattern.
 *
 * Supported patterns:
 * - **Exact**: `"files.read"` matches only `"files.read"`.
 * - **Global**: `"*"` matches any permission.
 * - **Namespace**: `"files.*"` matches `"files.read"`, `"files.write"`,
 *   `"files.sub.delete"`, etc.
 *
 * Patterns are deliberately limited to these three forms. Arbitrary glob
 * or regular-expression semantics are not part of the core contract.
 *
 * @param permission - The concrete permission key to check (e.g., `"files.read"`).
 * @param pattern - The pattern to match against (e.g., `"files.*"` or `"*"`).
 * @returns `true` if the permission matches the pattern.
 */
export function matchesPermission(permission: string, pattern: string): boolean {
  if (pattern === "*") {
    return true;
  }
  if (pattern.endsWith(".*") && pattern.length > 2) {
    // Remove only the "*" to keep the dot: "files.*" → prefix "files."
    const prefix = pattern.slice(0, -1);
    const bare = prefix.slice(0, -1);
    return permission === bare || permission.startsWith(prefix);
  }
  return permission === pattern;
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
  at?: Date,
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
        if (entry.required) {
          throw new Error(
            `Source "${entry.sourceName}" referenced by plan "${planName}" was not found. Register the source before using the plan.`,
          );
        }
        // Optional missing source — skip silently
        continue;
      }
      targetSources.set(entry.sourceName, resolver);
    }
  } else {
    targetSources = new Map(sources);
  }

  const now = at ?? new Date();
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
        if (fact.scope === null) {
          throw new TypeError(
            `Contract violation: source "${name}" returned a fact with a null scope. Use undefined for global applicability, or provide a non-empty scope string.`,
          );
        }
        if (fact.scope !== undefined && fact.scope.length === 0) {
          throw new TypeError(
            `Contract violation: source "${name}" returned a fact with an empty string scope. Use undefined for global applicability, or provide a non-empty scope string.`,
          );
        }
        // Validate startsAt/expiresAt are valid ISO 8601 when present.
        if (fact.startsAt !== undefined) {
          const s = new Date(fact.startsAt).getTime();
          if (Number.isNaN(s)) {
            throw new TypeError(
              `Contract violation: source "${name}" returned a fact with an invalid startsAt "${fact.startsAt}"`,
            );
          }
        }
        if (fact.expiresAt !== undefined) {
          const e = new Date(fact.expiresAt).getTime();
          if (Number.isNaN(e)) {
            throw new TypeError(
              `Contract violation: source "${name}" returned a fact with an invalid expiresAt "${fact.expiresAt}"`,
            );
          }
        }
        allFacts.push(fact);
      }
    }
  }

  return allFacts;
}

/**
 * Check whether a fact matches the requested scope.
 *
 * - If the fact has no scope, it is global and matches any request.
 * - If the fact has a scope, it matches only when the request has the same scope.
 */
function isInScope(fact: AuthorizationFact, requestedScope?: string): boolean {
  if (fact.scope === undefined || fact.scope === null) {
    // Global fact — matches any scope request.
    return true;
  }
  // Scoped fact — matches only when the request asks for the same scope.
  return fact.scope === requestedScope;
}

/**
 * Result of checking a fact's temporal and schedule activity.
 */
type FactActivity =
  | { readonly active: true }
  | { readonly active: false; readonly reason: "expired" | "not-yet-active" };

/**
 * Parse a "HH:mm" string into total minutes from midnight.
 */
function timeToMinutes(t: string): number {
  const parts = t.split(":").map(Number);
  return (parts[0] ?? 0) * 60 + (parts[1] ?? 0);
}

/**
 * Check whether a time range with `start > end` is an overnight window
 * (spans midnight into the next day).
 *
 * Uses `>` not `>=` so that equal start/end (e.g., "09:00"–"09:00") is
 * treated as a normal zero-length window, not an overnight wrap.
 */
function isOvernightRange(start: string, end: string): boolean {
  return timeToMinutes(start) > timeToMinutes(end);
}

/**
 * Check whether the given time-of-day (in minutes from midnight) falls
 * within a time range that belongs to the current day.
 *
 * - Normal (start <= end): start <= time < end
 * - Overnight (start > end): only the evening portion (time >= start)
 *   belongs to the listed day; the early-morning portion (time < end)
 *   is handled by {@link isOvernightNextActive} on the next day.
 */
function isTimeInRangeSameDay(timeMinutes: number, start: string, end: string): boolean {
  const s = timeToMinutes(start);
  const e = timeToMinutes(end);
  if (s <= e) {
    return timeMinutes >= s && timeMinutes < e;
  }
  // Overnight: only the evening portion (>= start) belongs to the listed day.
  return timeMinutes >= s && timeMinutes < 1440;
}

/**
 * Full-range check (including overnight wrap) used when the current day
 * is the next day after the listed day. This is only used internally by
 * {@link isOvernightNextActive}.
 */
function isTimeInRangeNextDay(timeMinutes: number, end: string): boolean {
  return timeMinutes < timeToMinutes(end);
}

/**
 * Simple cache for Intl.DateTimeFormat instances keyed by locale+options.
 * Avoids re-creating formatters per-fact during evaluation.
 * Capped at 100 entries to prevent memory growth in long-running processes.
 */
const dateTimeFormatCache = new Map<string, Intl.DateTimeFormat>();
const CACHE_MAX_SIZE = 100;

function getDateTimeFormat(
  locale: string,
  options: Intl.DateTimeFormatOptions,
): Intl.DateTimeFormat {
  const key = `${locale}\x00${JSON.stringify(options)}`;
  let fmt = dateTimeFormatCache.get(key);
  if (!fmt) {
    if (dateTimeFormatCache.size >= CACHE_MAX_SIZE) {
      // Evict oldest entry (first key) to keep cache bounded
      const firstKey = dateTimeFormatCache.keys().next().value;
      if (firstKey !== undefined) {
        dateTimeFormatCache.delete(firstKey);
      }
    }
    fmt = new Intl.DateTimeFormat(locale, options);
    dateTimeFormatCache.set(key, fmt);
  }
  return fmt;
}

/**
 * Get the day-of-week name in the given IANA timezone for a UTC date.
 */
function getWeekdayInTimezone(date: Date, timezone: string): DayOfWeek {
  const formatter = getDateTimeFormat("en-US", {
    timeZone: timezone,
    weekday: "long",
  });
  return formatter.format(date).toLowerCase() as DayOfWeek;
}

/**
 * Get the date string in "YYYY-MM-DD" format in the given IANA timezone.
 */
function getDateInTimezone(date: Date, timezone: string): string {
  // Use toLocaleDateString with en-CA locale which produces YYYY-MM-DD.
  // The cached formatter avoids repeated allocations.
  const formatter = getDateTimeFormat("en-CA", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  });
  return formatter.format(date);
}

/**
 * Get the local time in the given IANA timezone as total minutes from midnight.
 */
function getTimeInTimezone(date: Date, timezone: string): number {
  const formatter = getDateTimeFormat("en-US", {
    timeZone: timezone,
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
  return timeToMinutes(formatter.format(date));
}

/**
 * Return the day after the given day.
 */
function nextDay(day: DayOfWeek): DayOfWeek {
  const idx = DAYS.indexOf(day);
  return DAYS[(idx + 1) % 7]!;
}

/**
 * Return the date string (YYYY-MM-DD) for the day after the given date.
 */
function nextDate(dateStr: string): string {
  const d = new Date(dateStr + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10);
}

/**
 * Check whether the current time (in minutes from midnight) falls within
 * the overnight extension of any of the given time ranges.
 *
 * An overnight window (start > end) on a given day also covers the next
 * day from midnight until the end time. This helper checks that condition.
 */
function isOvernightNextActive(
  timeMinutes: number,
  ranges: TimeRange[],
): boolean {
  for (const range of ranges) {
    if (isOvernightRange(range.start, range.end) && isTimeInRangeNextDay(timeMinutes, range.end)) {
      return true;
    }
  }
  return false;
}

/**
 * Check whether a fact's recurring schedule is active at the given
 * UTC date, by converting to the schedule's IANA timezone.
 *
 * - No schedule → always active (no constraint).
 * - Empty schedule (no weeks, no dates) → never active.
 * - Checks both weekly windows and date-specific windows.
 * - Multiple windows are OR'd (any match = active).
 * - Overnight windows (start > end) handled correctly.
 *
 * Known limitation: During DST transitions (spring-forward/fall-back),
 * the flat "minutes from midnight" arithmetic may be off by one hour
 * for overnight windows that span the transition. This affects only
 * a few hours per year and is a known trade-off to avoid introducing
 * an external timezone library.
 */
function isScheduleActive(
  schedule: RecurringSchedule,
  at: Date,
): boolean {
  const weekday = getWeekdayInTimezone(at, schedule.timezone);
  const dateStr = getDateInTimezone(at, schedule.timezone);
  const timeMinutes = getTimeInTimezone(at, schedule.timezone);

  // Check weekly windows
  for (const week of schedule.weeks ?? []) {
    // Check on the listed day
    if (week.day === weekday) {
      for (const range of week.times) {
        if (isTimeInRangeSameDay(timeMinutes, range.start, range.end)) {
          return true;
        }
      }
    }
    // Check the next day for overnight windows
    const dayAfter = nextDay(week.day);
    if (dayAfter === weekday) {
      if (isOvernightNextActive(timeMinutes, week.times)) {
        return true;
      }
    }
  }

  // Check date windows
  for (const dw of schedule.dates ?? []) {
    // Check on the listed date
    if (dw.date === dateStr) {
      for (const range of dw.times) {
        if (isTimeInRangeSameDay(timeMinutes, range.start, range.end)) {
          return true;
        }
      }
    }
    // Check the next date for overnight windows
    const dateAfter = nextDate(dw.date);
    if (dateAfter === dateStr) {
      if (isOvernightNextActive(timeMinutes, dw.times)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Check whether a fact is temporally active at the given time.
 *
 * Uses a half-open interval where `startsAt` is inclusive and `expiresAt` is exclusive.
 * - Missing `startsAt` → active immediately.
 * - Missing `expiresAt` → never expires.
 */
function isTemporallyActive(
  fact: AuthorizationFact,
  at: Date,
): FactActivity {
  const time = at.getTime();

  if (fact.startsAt !== undefined) {
    const start = new Date(fact.startsAt).getTime();
    if (Number.isNaN(start)) {
      return { active: false, reason: "not-yet-active" };
    }
    if (time < start) {
      return { active: false, reason: "not-yet-active" };
    }
  }

  if (fact.expiresAt !== undefined) {
    const end = new Date(fact.expiresAt).getTime();
    if (Number.isNaN(end)) {
      return { active: false, reason: "expired" };
    }
    if (time >= end) {
      return { active: false, reason: "expired" };
    }
  }

  return { active: true };
}

/**
 * Evaluate all facts against a single permission and return the decision.
 *
 * Logic:
 * 1. Filter to pattern-matching facts (exact, global `*`, or namespace `files.*`).
 * 2. Evaluate each matching fact's scope, temporal, and schedule activity.
 * 3. If any active denial exists → deny (matching-denial).
 * 4. If any active grant exists → allow.
 * 5. If matching facts exist but all are out-of-scope → deny (out-of-scope).
 * 6. If matching facts exist but all are temporally inactive → deny (expired or not-yet-active).
 * 7. Otherwise → deny (no-grant).
 */
function evaluate(
  facts: AuthorizationFact[],
  permission: string,
  options?: { scope?: string; at?: Date },
): AuthorizationResult {
  const matching = facts.filter((f) => matchesPermission(permission, f.permission));
  if (matching.length === 0) {
    return { decision: "deny", reason: "no-grant" };
  }

  const requestedScope = options?.scope;
  const at = options?.at ?? new Date();

  // Separate facts by scope, temporal activity, schedule, and effect.
  const activeGrants: AuthorizationFact[] = [];
  const activeDenials: AuthorizationFact[] = [];
  const expired: AuthorizationFact[] = [];
  const notYetActive: AuthorizationFact[] = [];
  const outsideSchedule: AuthorizationFact[] = [];
  const outOfScope: AuthorizationFact[] = [];

  for (const fact of matching) {
    // Scope check first
    if (!isInScope(fact, requestedScope)) {
      outOfScope.push(fact);
      continue;
    }

    // Temporal check
    const temporal = isTemporallyActive(fact, at);
    if (!temporal.active) {
      if (temporal.reason === "expired") {
        expired.push(fact);
      } else {
        notYetActive.push(fact);
      }
      continue;
    }

    // Schedule check
    if (fact.schedule !== undefined) {
      const scheduleActive = isScheduleActive(fact.schedule, at);
      if (!scheduleActive) {
        outsideSchedule.push(fact);
        continue;
      }
    }

    // Active fact — evaluate effect
    if (fact.effect === "deny") {
      activeDenials.push(fact);
    } else {
      activeGrants.push(fact);
    }
  }

  if (activeDenials.length > 0) {
    return { decision: "deny", reason: "matching-denial" };
  }

  if (activeGrants.length > 0) {
    return { decision: "allow", reason: null };
  }

  // All matching facts were inactive — pick the most specific reason.
  // Priority order: scope > absolute time > schedule > future start.
  // This is a deliberate choice: scope is fundamental (you cannot access
  // what isn't yours), then absolute expiry (a lapsed permission), then
  // schedule mismatch (outside business hours), then future activation.
  if (outOfScope.length > 0) {
    return { decision: "deny", reason: "out-of-scope" };
  }
  if (expired.length > 0) {
    return { decision: "deny", reason: "expired" };
  }
  if (outsideSchedule.length > 0) {
    return { decision: "deny", reason: "outside-schedule" };
  }
  if (notYetActive.length > 0) {
    return { decision: "deny", reason: "not-yet-active" };
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
   * @param permission - The permission key to check.
   * @param options - Optional scope and evaluation time.
   * @returns `true` if the permission is granted, `false` otherwise.
   */
  async can(permission: string, options?: EvaluateOptions): Promise<boolean> {
    const result = await this.decide(permission, options);
    return result.decision === "allow";
  }

  /**
   * Check a permission and return a structured result.
   *
   * Unlike `can`, `decide` returns a full `AuthorizationResult` with
   * a stable reason code, suitable for auditing and diagnostics.
   *
   * @param permission - The permission key to check.
   * @param options - Optional scope and evaluation time.
   */
  async decide(permission: string, options?: EvaluateOptions): Promise<AuthorizationResult> {
    if (this.sources.size === 0) {
      throw new Error(
        "No sources registered on the Mizan instance. Register at least one source via registerSource() or useMemoryAdapter() before calling can/decide.",
      );
    }

    const at = options?.at ?? new Date();
    const facts = await collectFacts(this.sources, this.plans, this.principalId, this.planName, at);
    return evaluate(facts, permission, { ...options, at });
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
