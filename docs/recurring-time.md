# Recurring-time contract

`evaluate` accepts `EffectiveFact.schedules`, a readonly array of independent activity restrictions. All entries must match, alongside the fact's absolute validity and scope. An omitted array or `[]` adds no recurring restriction. A single schedule with empty `weeks` and `dates` never matches. Each schedule must provide `weeks`, `dates`, or both.

```ts
const fact = {
  permission: "cars.delete",
  effect: "grant",
  schedules: [{
    timezone: "UTC",
    weeks: [{ day: "monday", times: [{ start: "09:00", end: "17:00" }] }],
  }],
} as const;
```

## Windows

A schedule contains weekly windows with lowercase English weekday names, date windows with strict Gregorian `YYYY-MM-DD` dates, or both. Dates use years `0001` through `9999`. Windows within one schedule are alternatives. Independent schedules are conjunctive, so an assignment restriction cannot become an alternative to a permission restriction.

Times are exactly `HH:mm`, from `00:00` through `23:59`. Start is inclusive; end is exclusive. Seconds and milliseconds remain inside their containing minute. Equal endpoints define an empty window, not an all-day grant. `24:00` is unsupported.

When start is later than end, the window crosses midnight. Its late part applies on its anchor weekday/date. Its early part applies only on the immediately following local calendar day. Calendar adjacency includes week, month, leap-day and year rollovers. It does not mean 24 elapsed hours.

## Timezones and DST

Each schedule names an explicit runtime-supported IANA timezone, including `UTC`. Fixed-offset identifiers are rejected. The implementation uses standard `Intl` APIs with Gregorian calendar, Latin digits and a 00-through-23 hour cycle. It never uses the server's implicit local timezone. Zone rules come from the runtime's timezone database.

An instant matches its local wall-clock label. During spring-forward, missing labels never occur and never match. During fall-back, both instants with the same repeated label match. Endpoints are not shifted to fill a gap, and no earlier/later fold offset is chosen. Overnight windows use adjacent local calendar dates across DST, not an instant minus 24 hours.

Absolute validity remains `startsAt <= at < expiresAt`. Evaluation time and absolute bounds remain safe integer epoch milliseconds. An applicable scheduled fact requires a Date-representable instant; projection failure raises `AuthorizationFault`. Era-aware calendar projection prevents BCE instants from matching CE date windows.

## Validation and decisions

All supplied schedules are validated before permission, recognition, scope or absolute-time filtering. Malformed denials cannot disappear as inactive facts. Unknown fields, invalid zones/dates/times, sparse arrays, accessors and non-data schedule objects raise `AuthorizationFault`.

Schedule inactivity grants nothing. It adds no new public decision code. An active matching denial still returns `explicit-deny`; a known action without an applicable grant returns `no-applicable-grant`. Recognition exceptions require an active matching wildcard grant.

## Gallery and normalization

The preserved gallery's UTC weekday business hours map to one schedule entry. Disabling that restriction omits the entry. Its controls and implementation are unchanged by #63; #64 owns migration. The old evaluator and its historical result codes are not changed by this contract.

`expandRoles` validates and copies schedules on role permissions, assignments, and direct facts. It appends assignment and permission schedules as separate entries, so the evaluator requires both restrictions to match. A malformed schedule raises `AuthorizationFault` even on an unused role, an empty assignment, or a fact later omitted for a scope conflict or empty absolute interval. The singular `schedule` field remains unsupported.
