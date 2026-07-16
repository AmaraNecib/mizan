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
  /** `true` = grant, `false` = denial. */
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
 * @param options - Adapters, plans, and policy configuration.
 * @returns An authorization handle.
 */
export function createMizan(): Mizan {
  // TODO(#24): Implement full createMizan
  return new Mizan();
}

/**
 * Authorization handle created by `createMizan`.
 *
 * This is the public entry point for all authorization operations.
 * The class shape is intentionally minimal in v0.1 — extensions
 * (resource-aware checks, guards, plans, management) are added through
 * explicit seams without changing the base API.
 */
export class Mizan {
  // Internal state will be added as implementation progresses.
}

/**
 * Check whether a principal has a permission.
 *
 * @returns `true` if the permission is granted, `false` otherwise.
 */
export async function can(
  _permission: string,
  _options?: { principalId?: string },
): Promise<boolean> {
  // TODO(#24): Implement first decision path
  return false;
}

/**
 * Check a permission and return a structured result.
 *
 * Unlike `can`, `decide` returns a full `AuthorizationResult` with
 * a stable reason code and optional explanation, suitable for auditing
 * and diagnostics.
 */
export async function decide(
  _permission: string,
  _options?: { principalId?: string },
): Promise<AuthorizationResult> {
  // TODO(#24): Implement first decision path
  return {
    decision: "deny",
    reason: "no-grant",
    explanation: "Not yet implemented — first decision path pending.",
  };
}
