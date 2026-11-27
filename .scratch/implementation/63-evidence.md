# #63 implementation evidence

Base: `fd30fb5fe9a40c1a87b5404477502dfe9cd8276f` (clean before edits). Tier: High-assurance. Seam: public `@mizan/core` `evaluate` with `EffectiveFact`.

## RED → GREEN

- RED command: `bun test packages/core/__tests__/direct-evaluation.test.ts`. Result: 55 passed, 2 failed; both new checks failed with `AuthorizationFault: Fact contains an unsupported field` at the existing `FACT_KEYS` check. This confirmed that `evaluate` had no schedule contract.
- GREEN command: `bun test packages/core/__tests__/direct-evaluation.test.ts`. Result after initial integration: 57 passed, 0 failed.
- Expanded focused command: `bun test packages/core/__tests__/direct-evaluation.test.ts`. Result: 68 passed, 0 failed, 119 assertions.
- Type check: `bun run typecheck` → core, memory, and interactive-decision-demo passed.
- Lint: `bun run lint` → core, memory, and interactive-decision-demo passed.
- Full verification via `heavy_run`: `bun run test && bun run build` → core 218 passed, memory 16 passed, and all three package builds passed. Core emitted `Built ESM core consumer passed`.
- Frozen install: `bun install --frozen-lockfile` installed already-locked tooling; no dependency declarations or lockfiles changed.

## Coverage added

UTC weekly/date windows, intra-schedule OR and inter-schedule AND, empty conjunction versus inactive explicit-empty schedule, weekly Sunday-to-Monday and leap-day/date overnight rollover, New York gap/fold and Berlin gap/fold wall-clock behavior, absolute validity/scope intersection, denial precedence, malformed schedules before filtering, unsupported singular field, and out-of-Date-range scheduled instant faults. Public type test verifies readonly schedule literals through `EffectiveFact` and rejects singular `schedule`.

## Integration note

`ActivitySchedule` is exported from `packages/core/src/recurring-time.ts` and used by `EffectiveFact` in `direct-evaluation.ts`. Do not change `packages/core/src/index.ts` in this lane. Manager coordination is needed to add the shared named `ActivitySchedule` export during integration.
