import {
  accept,
  createAuthorizer,
  type Acceptance,
  type Source,
} from "@mizan/compose";

const riskPolicy = { riskLevels: ["low", "high", "critical"] } as const;
type Context = { readonly userId: string; readonly tenantId: string };
const source: Source<Context> = {
  contribution: "permissions",
  recognitionDomains: ["catalog"],
  resolve: (query) => ({
    status: "complete",
    binding: {
      subjectId: query.context.userId,
      partitionKey: query.context.tenantId,
      action: query.action,
      scope: { tenant: query.context.tenantId },
    },
    contribution: "permissions",
    recognitionDomains: ["catalog"],
    snapshot: { facts: [], knownActions: ["files.read"] },
    assurance: { consistency: "current", dataAsOf: query.startedAt },
  }),
};
const requirements: Acceptance = { consistency: "current", maxAgeMs: 500 };
const plan = accept(source, requirements);
const sensitive = {
  source: plan,
  recognitionRequirements: ["catalog"],
  policy: { risk: "critical" },
} as const;
const authorizer = createAuthorizer({
  policy: riskPolicy,
  bindContext: (context: Context) => ({
    subjectId: context.userId,
    partitionKey: context.tenantId,
    scope: { tenant: context.tenantId },
  }),
  actions: { "files.read": sensitive, "files.write": { source: plan, recognitionRequirements: [] } },
});
const request = authorizer.forContext({ userId: "u1", tenantId: "t1" });
request.can("files.read");
request.decide("files.write");
request.decideDynamic({ action: "runtime.read" });

// @ts-expect-error an unregistered risk cannot be inferred from an action override
createAuthorizer({ policy: riskPolicy, bindContext: (context: Context) => ({ subjectId: context.userId, partitionKey: context.tenantId, scope: {} }), actions: { "files.read": { source: plan, recognitionRequirements: [], policy: { risk: "urgent" } } } });
// @ts-expect-error static action keys remain literal
request.can("files.delete");
// @ts-expect-error the public call surface cannot accept policy or assurance overrides
request.decide("files.read", { maxAgeMs: 0 });
const narrowSource: Source<{ userId: string; tenantId: string; admin: true }> = source as Source<{ userId: string; tenantId: string; admin: true }>;
// @ts-expect-error source context cannot be narrower than the context bound by the authorizer
createAuthorizer({ policy: riskPolicy, bindContext: (context: Context) => ({ subjectId: context.userId, partitionKey: context.tenantId, scope: {} }), actions: { "files.read": { source: accept(narrowSource, requirements), recognitionRequirements: [] } } });
void authorizer;
