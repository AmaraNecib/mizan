import { describe, expect, it } from "bun:test";
import {
  AuthorizationFault,
  accept,
  createAuthorizer,
  type Source,
  type SourceOutcome,
} from "@mizan/compose";

const binding = {
  subjectId: "user-1",
  partitionKey: "tenant-a",
  scope: { tenant: "a" },
} as const;
const requirements = { consistency: "snapshot", maxAgeMs: 1_000 } as const;
const policy = { riskLevels: ["low", "high"] } as const;

function complete(action = "files.read"): SourceOutcome {
  return {
    status: "complete",
    binding: { ...binding, action },
    contribution: "permissions",
    recognitionDomains: ["catalog"],
    snapshot: {
      knownActions: ["files.read", "runtime.read"],
      facts: [{ permission: action, effect: "grant" }],
    },
    assurance: { consistency: "current", dataAsOf: 1_000, revision: "r1" },
  };
}

function makeAuthorizer(resolve: Source<unknown>["resolve"]) {
  const source: Source<{ userId: string; tenantId: string }> = {
    contribution: "permissions",
    recognitionDomains: ["catalog"],
    resolve,
  };
  const plan = accept(source, requirements);
  const definition = { source: plan, recognitionRequirements: ["catalog"] };
  return createAuthorizer({
    policy,
    bindContext: (context: { userId: string; tenantId: string }) => ({
      subjectId: context.userId,
      partitionKey: context.tenantId,
      scope: { tenant: context.tenantId === "tenant-a" ? "a" : "b" },
    }),
    actions: { "files.read": definition },
    routes: { "*": definition },
    clock: () => 1_000,
  });
}

describe("@mizan/compose one-source authorizer", () => {
  it("binds one complete source and delegates the decision to core", async () => {
    const authorizer = makeAuthorizer(async (query) => complete(query.action));
    const handle = authorizer.forContext({ userId: "user-1", tenantId: "tenant-a" });
    await expect(handle.decide("files.read")).resolves.toEqual({
      outcome: "allow", code: "granted", recognition: "known",
    });
    await expect(handle.can("files.read")).resolves.toBe(true);
  });

  it("reacquires on every decision and projects deny and indeterminate to false", async () => {
    let calls = 0;
    const authorizer = makeAuthorizer(async (query) => {
      calls += 1;
      if (calls === 2) return { status: "unavailable", code: "offline" };
      return { ...complete(query.action), snapshot: { knownActions: [query.action], facts: [] } };
    });
    const handle = authorizer.forContext({ userId: "user-1", tenantId: "tenant-a" });
    await expect(handle.can("files.read")).resolves.toBe(false);
    await expect(handle.decide("files.read")).resolves.toEqual({
      outcome: "indeterminate", code: "evidence-unavailable",
    });
    expect(calls).toBe(2);
  });

  it("recognizes runtime keys on the explicit dynamic path", async () => {
    const authorizer = makeAuthorizer(async (query) => complete(query.action));
    const result = await authorizer.forContext({ userId: "user-1", tenantId: "tenant-a" })
      .decideDynamic({ action: "runtime.read" });
    expect(result).toEqual({ outcome: "allow", code: "granted", recognition: "known" });
  });

  it("supports runtime-only authorizers with a namespace route", async () => {
    const source: Source<unknown> = {
      contribution: "permissions",
      recognitionDomains: ["catalog"],
      resolve: async (query) => complete(query.action),
    };
    const plan = accept(source, requirements);
    const authorizer = createAuthorizer({
      policy,
      bindContext: () => binding,
      actions: {},
      routes: { "runtime.*": { source: plan, recognitionRequirements: ["catalog"] } },
      clock: () => 1_000,
    });
    await expect(authorizer.forContext({}).decideDynamic({ action: "runtime.read" }))
      .resolves.toMatchObject({ outcome: "allow" });
  });

  it("returns incomplete evidence for a miss without calling core", async () => {
    const authorizer = makeAuthorizer(async () => ({ status: "miss" }));
    await expect(authorizer.forContext({ userId: "user-1", tenantId: "tenant-a" }).decide("files.read"))
      .resolves.toEqual({ outcome: "indeterminate", code: "evidence-incomplete" });
  });

  it("rejects binding mismatches and malformed source output with a typed fault", async () => {
    const wrongBinding = makeAuthorizer(async (query) => ({
      ...complete(query.action), binding: { ...binding, action: query.action, partitionKey: "other" },
    }));
    await expect(wrongBinding.forContext({ userId: "user-1", tenantId: "tenant-a" }).decide("files.read"))
      .rejects.toBeInstanceOf(AuthorizationFault);

    const malformed = makeAuthorizer(async () => null as never);
    await expect(malformed.forContext({ userId: "user-1", tenantId: "tenant-a" }).decide("files.read"))
      .rejects.toBeInstanceOf(AuthorizationFault);
  });

  it("rejects malformed evidence and unsupported fields instead of treating them as misses", async () => {
    const mismatchedDomains = makeAuthorizer(async (query) => ({
      ...complete(query.action), recognitionDomains: ["other"],
    }));
    await expect(mismatchedDomains.forContext({ userId: "user-1", tenantId: "tenant-a" }).decide("files.read"))
      .rejects.toBeInstanceOf(AuthorizationFault);

    const hiddenDecision = makeAuthorizer(async (query) => ({
      ...complete(query.action), decision: "allow",
    } as never));
    await expect(hiddenDecision.forContext({ userId: "user-1", tenantId: "tenant-a" }).decide("files.read"))
      .rejects.toBeInstanceOf(AuthorizationFault);

    const authorizer = makeAuthorizer(async (query) => complete(query.action));
    expect(() => authorizer.forContext({ userId: "user-1", tenantId: "tenant-a" })
      .decideDynamic({ action: "files.read", policy: {} } as never)).toThrow(AuthorizationFault);
  });

  it("copies the context binding and rejects unsupported deferred behavior", async () => {
    const source: Source<unknown> = {
      contribution: "permissions", recognitionDomains: ["catalog"],
      resolve: async (query) => complete(query.action),
    };
    const context = { userId: "user-1", tenantId: "tenant-a" };
    const authorizer = createAuthorizer({
      policy,
      bindContext: (value: typeof context) => ({ ...binding, subjectId: value.userId }),
      actions: { "files.read": { source: accept(source, requirements), recognitionRequirements: ["catalog"] } },
      clock: () => 1_000,
    });
    const handle = authorizer.forContext(context);
    context.userId = "changed";
    await expect(handle.decide("files.read")).resolves.toMatchObject({ outcome: "allow" });

    expect(() => createAuthorizer({
      policy,
      bindContext: () => binding,
      actions: { "files.read": { source: accept(source, requirements), recognitionRequirements: ["catalog"], guards: [] } },
    } as never)).toThrow(AuthorizationFault);
    expect(() => createAuthorizer({
      policy: { riskLevels: ["low", "low"] },
      bindContext: () => binding,
      actions: { "files.read": { source: accept(source, requirements), recognitionRequirements: [] } },
    } as never)).toThrow(AuthorizationFault);
  });

  it("isolates policy and route configuration from later caller mutation", async () => {
    const routePolicy: { unknownPermissions: "deny" | "allow-if-wildcard-granted" } = {
      unknownPermissions: "allow-if-wildcard-granted",
    };
    const source: Source<unknown> = {
      contribution: "permissions",
      recognitionDomains: ["catalog"],
      resolve: async (query) => ({
        ...complete(query.action),
        snapshot: { knownActions: [], facts: [{ permission: "*", effect: "grant" }] },
      }),
    };
    const definition = {
      source: accept(source, requirements),
      recognitionRequirements: ["catalog"],
      policy: routePolicy,
    };
    const authorizer = createAuthorizer({
      policy,
      bindContext: () => binding,
      actions: { "files.read": definition },
      routes: { "runtime.*": definition },
      clock: () => 1_000,
    });
    routePolicy.unknownPermissions = "deny";
    await expect(authorizer.forContext({}).decideDynamic({ action: "runtime.read" }))
      .resolves.toMatchObject({ outcome: "allow", recognition: "wildcard-exception" });
  });

  it("preserves non-enumerable risk policy fields when copying checked policy", async () => {
    const source: Source<unknown> = {
      contribution: "permissions", recognitionDomains: ["catalog"],
      resolve: async (query) => ({ ...complete(query.action), snapshot: {
        knownActions: [], facts: [{ permission: "*", effect: "grant" }],
      } }),
    };
    const hiddenPolicy = {
      riskLevels: ["low"],
      defaults: { unknownPermissions: "allow-if-wildcard-granted" },
      byRisk: { low: { unknownPermissions: "deny" } },
    };
    Object.defineProperty(hiddenPolicy, "risk", {
      value: { "runtime.*": "low" }, enumerable: false,
    });
    const authorizer = createAuthorizer({
      policy: hiddenPolicy as never, bindContext: () => binding, actions: {},
      routes: { "runtime.*": { source: accept(source, requirements), recognitionRequirements: ["catalog"] } },
      clock: () => 1_000,
    });
    await expect(authorizer.forContext({}).decideDynamic({ action: "runtime.disabled" }))
      .resolves.toEqual({ outcome: "deny", code: "unknown-action" });
  });

  it("accepts native abort signals and stops before acquisition when already aborted", async () => {
    let calls = 0;
    const authorizer = makeAuthorizer(async (query) => {
      calls += 1;
      return complete(query.action);
    });
    const active = new AbortController();
    await expect(authorizer.forContext({ userId: "user-1", tenantId: "tenant-a" }, { signal: active.signal })
      .decide("files.read")).resolves.toMatchObject({ outcome: "allow" });
    const cancelled = new AbortController();
    cancelled.abort();
    await expect(authorizer.forContext({ userId: "user-1", tenantId: "tenant-a" }, { signal: cancelled.signal })
      .decide("files.read")).resolves.toEqual({ outcome: "indeterminate", code: "cancelled" });
    expect(calls).toBe(1);
  });

  it("rejects a clock sample lower than the previous sample from this authorizer", async () => {
    const samples = [1_000, 1_001, 1_000, 1_001];
    const authorizer = createAuthorizer({
      policy,
      bindContext: () => binding,
      actions: {
        "files.read": { source: accept({
          contribution: "permissions", recognitionDomains: ["catalog"],
          resolve: async (query) => complete(query.action),
        }, requirements), recognitionRequirements: ["catalog"] },
      },
      clock: () => samples.shift()!,
    });
    const handle = authorizer.forContext({});
    await expect(handle.decide("files.read")).resolves.toMatchObject({ outcome: "allow" });
    await expect(handle.decide("files.read")).rejects.toBeInstanceOf(AuthorizationFault);
  });

  it("shares the clock high-water mark across handles from one authorizer", async () => {
    const samples = [1_000, 1_001, 1_000, 1_001];
    const authorizer = createAuthorizer({
      policy,
      bindContext: () => binding,
      actions: {
        "files.read": { source: accept({
          contribution: "permissions", recognitionDomains: ["catalog"],
          resolve: async (query) => complete(query.action),
        }, requirements), recognitionRequirements: ["catalog"] },
      },
      clock: () => samples.shift()!,
    });
    await expect(authorizer.forContext({}).decide("files.read")).resolves.toMatchObject({ outcome: "allow" });
    await expect(authorizer.forContext({}).can("files.read")).rejects.toBeInstanceOf(AuthorizationFault);
  });

  it("accepts equal clock samples and keeps clock state per authorizer", async () => {
    const samples = [2_000, 2_000, 1_000, 1_001];
    const sharedClock = () => samples.shift()!;
    const makeWithClock = (clock: () => number) => createAuthorizer({
      policy,
      bindContext: () => binding,
      actions: {
        "files.read": { source: accept({
          contribution: "permissions", recognitionDomains: ["catalog"],
          resolve: async (query) => complete(query.action),
        }, requirements), recognitionRequirements: ["catalog"] },
      },
      clock,
    });
    const first = makeWithClock(sharedClock).forContext({});
    await expect(first.decide("files.read")).resolves.toMatchObject({ outcome: "allow" });
    const second = makeWithClock(sharedClock).forContext({});
    await expect(second.decide("files.read")).resolves.toMatchObject({ outcome: "allow" });
  });

  it("keeps the high-water mark after invalid and decreasing clock samples", async () => {
    const samples: unknown[] = [1_000, 1_002, Number.NaN, 1_001, 1_001, 1_002, 1_002];
    const authorizer = createAuthorizer({
      policy,
      bindContext: () => binding,
      actions: {
        "files.read": { source: accept({
          contribution: "permissions", recognitionDomains: ["catalog"],
          resolve: async (query) => complete(query.action),
        }, requirements), recognitionRequirements: ["catalog"] },
      },
      clock: () => samples.shift() as number,
    });
    const handle = authorizer.forContext({});
    await expect(handle.decide("files.read")).resolves.toMatchObject({ outcome: "allow" });
    await expect(handle.decide("files.read")).rejects.toBeInstanceOf(AuthorizationFault);
    await expect(handle.decide("files.read")).rejects.toBeInstanceOf(AuthorizationFault);
    await expect(handle.decide("files.read")).rejects.toBeInstanceOf(AuthorizationFault);
    await expect(handle.decide("files.read")).resolves.toMatchObject({ outcome: "allow" });
  });

  it("checks actual clock samples despite out-of-order async completion", async () => {
    let releaseFirst!: () => void;
    let releaseSecond!: () => void;
    let resolvers = 0;
    const authorizer = createAuthorizer({
      policy,
      bindContext: () => binding,
      actions: {
        "files.read": { source: accept({
          contribution: "permissions", recognitionDomains: ["catalog"],
          resolve: async (query) => {
            resolvers += 1;
            await new Promise<void>((resolve) => {
              if (resolvers === 1) releaseFirst = resolve;
              else releaseSecond = resolve;
            });
            return complete(query.action);
          },
        }, requirements), recognitionRequirements: ["catalog"] },
      },
      clock: (() => {
        const samples = [1_000, 1_001, 1_003, 1_002];
        return () => samples.shift()!;
      })(),
    });
    const handle = authorizer.forContext({});
    const first = handle.decide("files.read");
    const second = handle.decide("files.read");
    await Promise.resolve();
    releaseSecond();
    await expect(second).resolves.toMatchObject({ outcome: "allow" });
    releaseFirst();
    await expect(first).rejects.toBeInstanceOf(AuthorizationFault);
  });

  it("returns cancelled when acquisition is aborted while pending", async () => {
    let release!: (value: SourceOutcome) => void;
    const authorizer = makeAuthorizer((query) => new Promise<SourceOutcome>((resolve) => {
      release = (value) => resolve(value);
      void query;
    }));
    const controller = new AbortController();
    const pending = authorizer.forContext({ userId: "user-1", tenantId: "tenant-a" }, { signal: controller.signal })
      .decide("files.read");
    await Promise.resolve();
    controller.abort();
    release(complete("files.read"));
    await expect(pending).resolves.toEqual({ outcome: "indeterminate", code: "cancelled" });
  });

  it("preserves the original source rejection through decide and can", async () => {
    const failure = new Error("source failure");
    const authorizer = makeAuthorizer(async () => { throw failure; });
    const handle = authorizer.forContext({ userId: "user-1", tenantId: "tenant-a" });
    await expect(handle.decide("files.read")).rejects.toBe(failure);
    await expect(handle.can("files.read")).rejects.toBe(failure);
  });

  it("treats complete-empty evidence as a decision, not missing evidence", async () => {
    const authorizer = makeAuthorizer(async (query) => ({
      ...complete(query.action),
      snapshot: { knownActions: [query.action], facts: [] },
    }));
    await expect(authorizer.forContext({ userId: "user-1", tenantId: "tenant-a" }).decide("files.read"))
      .resolves.toEqual({ outcome: "deny", code: "no-applicable-grant" });
  });

  it("rejects malformed dynamic actions and missing recognition-domain setup", async () => {
    const authorizer = makeAuthorizer(async (query) => complete(query.action));
    const handle = authorizer.forContext({ userId: "user-1", tenantId: "tenant-a" });
    expect(() => handle.decideDynamic({ action: "bad action" })).toThrow(AuthorizationFault);

    const source: Source<unknown> = {
      contribution: "permissions", recognitionDomains: ["catalog"],
      resolve: async (query) => complete(query.action),
    };
    expect(() => createAuthorizer({
      policy,
      bindContext: () => binding,
      actions: { "files.read": { source: accept(source, requirements), recognitionRequirements: ["missing"] } },
    })).toThrow(AuthorizationFault);
  });

  it("preserves source method receivers while isolating its declared configuration", async () => {
    const source = {
      contribution: "permissions",
      recognitionDomains: ["catalog"],
      resolve(query: Parameters<Source<unknown>["resolve"]>[0]) {
        return {
          ...complete(query.action),
          contribution: this.contribution,
          recognitionDomains: this.recognitionDomains,
        };
      },
    };
    const plan = accept(source, requirements);
    source.contribution = "changed";
    source.recognitionDomains[0] = "changed";
    const authorizer = createAuthorizer({
      policy,
      bindContext: () => binding,
      actions: { "files.read": { source: plan, recognitionRequirements: ["catalog"] } },
      clock: () => 1_000,
    });
    await expect(authorizer.forContext({}).decide("files.read")).resolves.toMatchObject({ outcome: "allow" });
  });

  it("rejects source and plan status accessors with AuthorizationFault", async () => {
    let getterCalls = 0;
    const sourceReply = Object.defineProperty({}, "status", { get() { getterCalls += 1; throw new Error("getter ran"); } });
    const sourceAuthorizer = makeAuthorizer(async () => sourceReply as never);
    const sourceHandle = sourceAuthorizer.forContext({ userId: "user-1", tenantId: "tenant-a" });
    await expect(sourceHandle.decide("files.read")).rejects.toBeInstanceOf(AuthorizationFault);
    await expect(sourceHandle.can("files.read")).rejects.toBeInstanceOf(AuthorizationFault);

    const source = { contribution: "permissions", recognitionDomains: ["catalog"], resolve: async () => complete() };
    const plan = accept(source, requirements);
    const planReply = Object.defineProperty({}, "status", { get() { getterCalls += 1; throw new Error("getter ran"); } });
    const authorizer = createAuthorizer({
      policy, bindContext: () => binding,
      actions: { "files.read": { source: { ...plan, resolve: async () => planReply as never }, recognitionRequirements: ["catalog"] } },
      clock: () => 1_000,
    });
    const planHandle = authorizer.forContext({});
    await expect(planHandle.decide("files.read")).rejects.toBeInstanceOf(AuthorizationFault);
    await expect(planHandle.can("files.read")).rejects.toBeInstanceOf(AuthorizationFault);
    expect(getterCalls).toBe(0);
  });

  it("isolates receipt requirements and output metadata across resolutions", async () => {
    const source = { contribution: "permissions", recognitionDomains: ["catalog"], resolve: async (query: Parameters<Source<unknown>["resolve"]>[0]) => complete(query.action) };
    const plan = accept(source, requirements);
    expect(Object.isFrozen(plan.recognitionDomains)).toBe(true);
    expect(Object.isFrozen(plan.contributions)).toBe(true);
    let calls = 0;
    const wrappedPlan = {
      ...plan,
      async resolve(query: Parameters<typeof plan.resolve>[0]) {
        const result = await plan.resolve(query);
        calls += 1;
        if (this.contributions[0] === "permissions" && calls === 1 && result.status === "complete") {
          (result.selected[0]!.requirements as { maxAgeMs: number }).maxAgeMs = 0;
        }
        return result;
      },
    };
    let now = 1_000;
    const authorizer = createAuthorizer({ policy, bindContext: () => binding,
      actions: { "files.read": { source: wrappedPlan, recognitionRequirements: ["catalog"] } }, clock: () => now });
    const handle = authorizer.forContext({});
    await expect(handle.decide("files.read")).resolves.toMatchObject({ outcome: "allow" });
    now += 1;
    await expect(handle.decide("files.read")).resolves.toMatchObject({ outcome: "allow" });
  });

  it("keeps structural plan method declarations isolated after construction", async () => {
    const source: Source<unknown> = {
      contribution: "permissions", recognitionDomains: ["catalog"],
      resolve: (query) => complete(query.action),
    };
    const accepted = accept(source, requirements);
    const contributions = ["permissions"];
    const domains = ["catalog"];
    const plan = {
      contributions, recognitionDomains: domains,
      async resolve(query: Parameters<typeof accepted.resolve>[0]) {
        const result = await accepted.resolve(query);
        if (result.status !== "complete") return result;
        return { ...result, selected: result.selected.map((receipt) => ({
          ...receipt, evidence: {
            ...receipt.evidence, contribution: this.contributions[0]!,
            recognitionDomains: this.recognitionDomains,
          },
        })) };
      },
    };
    const authorizer = createAuthorizer({
      policy, bindContext: () => binding,
      actions: { "files.read": { source: plan, recognitionRequirements: ["catalog"] } },
      clock: () => 1_000,
    });
    contributions[0] = "changed";
    domains[0] = "changed";
    await expect(authorizer.forContext({}).decide("files.read"))
      .resolves.toEqual({ outcome: "allow", code: "granted", recognition: "known" });
  });

  it("turns circular and deeply nested source facts into typed faults", async () => {
    const circular: Record<string, unknown> = { permission: "files.read", effect: "grant" };
    circular.scope = circular;
    const circularAuthorizer = makeAuthorizer(async (query) => ({
      ...complete(query.action), snapshot: { knownActions: [query.action], facts: [circular] },
    } as never));
    await expect(circularAuthorizer.forContext({ userId: "user-1", tenantId: "tenant-a" }).decide("files.read"))
      .rejects.toBeInstanceOf(AuthorizationFault);

    let nested: Record<string, unknown> = {};
    const deepFact: Record<string, unknown> = { permission: "files.read", effect: "grant", scope: nested };
    for (let i = 0; i < 200; i += 1) nested = { child: nested };
    deepFact.scope = nested;
    const deepAuthorizer = makeAuthorizer(async (query) => ({
      ...complete(query.action), snapshot: { knownActions: [query.action], facts: [deepFact] },
    } as never));
    await expect(deepAuthorizer.forContext({ userId: "user-1", tenantId: "tenant-a" }).decide("files.read"))
      .rejects.toBeInstanceOf(AuthorizationFault);
  });

  it("preserves static recognition, denies unknown routed keys, and honors explicit deny", async () => {
    const source: Source<unknown> = { contribution: "permissions", recognitionDomains: ["catalog"], resolve: async (query) => ({
      ...complete(query.action), snapshot: { knownActions: [], facts: [
        { permission: "*", effect: "grant" }, ...(query.action === "files.denied" ? [{ permission: query.action, effect: "deny" as const }] : []),
      ] },
    }) };
    const definition = { source: accept(source, requirements), recognitionRequirements: ["catalog"],
      policy: { unknownPermissions: "deny" as const } };
    const authorizer = createAuthorizer({ policy, bindContext: () => binding,
      actions: { "files.read": definition, "files.denied": definition }, routes: { "runtime.*": definition }, clock: () => 1_000 });
    const handle = authorizer.forContext({});
    await expect(handle.decide("files.read")).resolves.toMatchObject({ outcome: "allow", recognition: "known" });
    await expect(handle.decide("files.denied")).resolves.toMatchObject({ outcome: "deny", code: "explicit-deny" });
    await expect(handle.decideDynamic({ action: "runtime.read" })).resolves.toEqual({ outcome: "deny", code: "unknown-action" });
  });

  it("checks evidence age at decision time and recognizes runtime definitions independently of grants", async () => {
    let now = 1_000;
    const authorizer = createAuthorizer({
      policy,
      bindContext: () => binding,
      actions: {
        "files.read": { source: accept({
          contribution: "permissions", recognitionDomains: ["catalog"],
          resolve: async (query) => ({ ...complete(query.action), assurance: { consistency: "snapshot", dataAsOf: 1_000 } }),
        }, { consistency: "snapshot", maxAgeMs: 0 }), recognitionRequirements: ["catalog"] },
      },
      clock: () => now,
    });
    const handle = authorizer.forContext({});
    expect((await handle.decide("files.read")).outcome).toBe("allow");
    now += 1;
    expect(await handle.decide("files.read")).toEqual({ outcome: "indeterminate", code: "assurance-unmet" });
  });
});
