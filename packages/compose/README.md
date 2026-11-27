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

## Snapshot copy limits

Compose rejects oversized source snapshots with `AuthorizationFault`, including snapshots returned by host-authored structural plans. It never truncates facts or recognition information. These fixed limits apply independently at each source/plan validation boundary:

| Limit | Maximum |
| --- | --- |
| Slots in each source `facts` or `knownActions` array | 10,000 |
| Combined array slots and object properties visited inside both arrays | 100,000 |
| Combined UTF-16 code units in string values and object property names inside both arrays | 1,000,000 |
| Nesting depth from each array root at depth zero | 64 |

Repeated occurrences count separately, even when they reference the same object or string. Object property names count toward the text budget; numeric array index names do not. Circular data, accessors, holes, non-plain data and unsupported fields remain faults. Container entry budgets are checked before copying their children; the two root array lengths are checked before enumerating their keys. Exact static action recognition may append one key after these source limits.

An `accept` plan copies source snapshot data, and the authorizer copies the selected evidence again because structural plan wrappers can change it. The authorizer does not deep-copy the entire receipt tree or deep-copy the validated snapshot a third time before core evaluation. Core still performs its own full input validation and normalization. Complete-empty evidence, binding checks and retained acceptance requirements are unchanged.

These are deterministic traversal/copy limits, not an exact heap-byte or CPU-time guarantee. Source allocation happens before validation. JavaScript key reflection allocates a key list for a record before its width can be checked; Proxy traps and host callbacks can also execute arbitrary work. Metadata outside `facts` and `knownActions` is not covered by these snapshot budgets. Hosts must keep source implementations and input construction under their own resource controls. A host whose complete action-scoped snapshot exceeds a limit must change its source coverage or use trusted direct core evaluation, not drop grants or denials to fit. Core's direct evaluator and normalization limits are unchanged.

Issue 60 implements only one source. Fallback, multiple required contributors, guards, resource conditions, and their workflows are not supported; unknown configuration fields are rejected.
