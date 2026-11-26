# Security Wisdom

## Gregorian formatting needs an era for date-specific grants

`Intl.DateTimeFormat` returns era-relative years. Without an explicit era, a BCE instant can look like CE year 0001 and match a date-specific grant. The direct evaluator accepts negative epoch milliseconds, so this is a reachable false allow.

**Always**: Request the Gregorian era and convert BC years to astronomical year numbering before local calendar arithmetic. Keep a public evaluator regression that denies a BCE instant against a CE date grant.

## Timezone rejection must cover aliases and case variants

`Intl.DateTimeFormat` accepts case-insensitive timezone names and fixed-offset aliases such as `GMT0` and `Etc/GMT`. A case-sensitive filter for `Etc/GMT+` misses both aliases and lowercase offset names.

**Always**: Enforce the declared timezone contract before constructing the formatter. Test rejected aliases through `evaluate` and `expandRoles`, plus supported UTC names so validation does not remove the documented exception.

## Duplicate source names silently override (🟠 Major)

`Map.set()` silently overwrites entries. If a denial source is registered then accidentally re-registered with a grant-only resolver, the denial disappears and authorization could flip to allow.

**Always**: Check for existing keys before registering. Throw on duplicates.

## Unavailable source must fail closed (🔴 Critical)

When a source returns `status: "unavailable"`, you cannot silently skip it — the unavailable source might contain a denial that overrides a grant from another source. Skipping it opens an allow path.

**Always**: Treat `"unavailable"` as a hard error — throw or return a structured denial. Never continue evaluation.

## Null outcome from resolver (🟠 Major)

A resolver can return `null` (or `undefined`) instead of a proper `SourceOutcome`. Accessing `.status` on null crashes with a cryptic `TypeError`, and if it somehow slips past, the authorization decision is undefined behavior.

**Always**: Validate the outcome object itself before accessing its properties. Throw a descriptive contract-violation error.

## Source should not expose decisions (💡 Design Principle)

The memory adapter returns `SourceOutcome` with facts only — no `decision` field. The core owns the decision. An adapter that smuggles a final allow/deny breaks the separation and can produce conflicting outcomes.

**Always**: Verify adapters return facts, not decisions. Test that `"decision" in outcome` is false.
