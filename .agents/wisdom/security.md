# Security Wisdom

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

## Copy validated data without changing its meaning

Compose review found that enumerable-only copies dropped checked policy fields, and shared receipt requirements let one resolution change later acceptance. Reading a status getter before validation also bypassed the typed-fault contract.

**Always**: Copy checked own data descriptors, including non-enumerable fields. Reject accessors before reading discriminants. Give method callbacks isolated declaration copies and each receipt its own acceptance requirements. Bound recursive data validation and reject cycles with `AuthorizationFault`.
