# @mizan/compose

`@mizan/compose` acquires one bound evidence result and sends its facts to `@mizan/core`. It does not own authentication, storage, caching, or authorization decisions.

```ts
import { accept, createAuthorizer, type Source } from "@mizan/compose";

type RequestContext = { userId: string; tenantId: string };
const source: Source<RequestContext> = {
  contribution: "permissions",
  recognitionDomains: ["catalog"],
  resolve: async (query) => ({
    status: "complete",
    binding: {
      subjectId: query.context.userId,
      partitionKey: query.context.tenantId,
      action: query.action,
      scope: { tenant: query.context.tenantId },
    },
    contribution: "permissions",
    recognitionDomains: ["catalog"],
    snapshot: {
      knownActions: ["files.read"],
      facts: [{ permission: "files.read", effect: "grant" }],
    },
    assurance: { consistency: "current", dataAsOf: query.startedAt },
  }),
};
const plan = accept(source, { consistency: "current", maxAgeMs: 1_000 });
const authorizer = createAuthorizer({
  policy: { riskLevels: ["low", "high"] },
  bindContext: (context: RequestContext) => ({
    subjectId: context.userId,
    partitionKey: context.tenantId,
    scope: { tenant: context.tenantId },
  }),
  actions: { "files.read": { source: plan, recognitionRequirements: ["catalog"] } },
  clock: () => 1_000,
});
const request = authorizer.forContext({ userId: "u1", tenantId: "t1" });
const decision = await request.decide("files.read");
const allowed = await request.can("files.read");
```

A complete empty snapshot is a valid answer and evaluates to deny when no grant applies. A `miss` becomes `evidence-incomplete`; an `unavailable` result becomes `evidence-unavailable`. Malformed output throws `AuthorizationFault`. `can()` is true only for an allow. Each call acquires evidence again. Keep the verified context stable for the lifetime of its request handle; Mizan copies the binding but does not deep-freeze host context.

Exact action keys are inferred from `actions`, and each exact key is registered as a known action. That static definition remains recognized even if the source omits it from `knownActions`; omission cannot revoke a static key. `unknownPermissions` applies to unknown keys selected by a route, not to an exact key. Use `decideDynamic({ action })` for runtime-defined keys, with runtime recognition supplied by the source. Namespace routes (`"files.*"`) and a global route (`"*"`) can select a source for runtime keys. A route does not define every matching action.

Each authorizer compares clock samples with its own last valid sample, in actual sample order across all calls and handles. Clock state belongs to the authorizer instance created at construction, but construction itself does not sample the clock. Equal samples are valid. Invalid or decreasing samples throw `AuthorizationFault` and do not replace the last valid sample. Separate authorizer instances remain independent, even when they use the same clock function. Async completion order does not change the order in which samples are checked. The clock tracks validity and monotonicity only; it does not cache evidence.

Issue 60 implements only one source. Fallback, multiple required contributors, guards, resource conditions, and their workflows are not supported; unknown configuration fields are rejected.
