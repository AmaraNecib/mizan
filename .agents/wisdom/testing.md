# Testing Wisdom

## Await all async assertions (🟡 Minor / false-positive risk)

`expect(promise).rejects.toThrow(...)` returns a promise — if you don't `await` it, the test can finish before the assertion runs, producing false positives. This applies to both `.rejects` and `.resolves`.

**Always**:
```typescript
// ✅ Correct
await expect(auth.can("x")).rejects.toThrow(/error/i);
await expect(auth.can("x")).resolves.toBe(true);

// ❌ Wrong — test can pass even if assertion fails
expect(auth.can("x")).rejects.toThrow(/error/i);
```

## Test contract violations explicitly

When the spec says "malformed output is surfaced as a developer-facing error", test every malformation path:

- Unknown status
- Missing or non-array facts (empty array is valid — means no facts)
- Null/undefined outcome
- Non-array facts
- Invalid fact entries (missing permission, unknown effect)

## Test the complete end-to-end path

Don't stop at unit-testing the evaluator in isolation. Wire up the real adapter (`useMemoryAdapter`) and verify the full principal → adapter → core → decision flow. This catches integration bugs in source registration and fact collection.

## Denial-overrides-grant must be tested cross-source

Test that a denial from source B overrides a grant from source A, not just within the same source list. The cross-source case is the one that most easily regresses.
