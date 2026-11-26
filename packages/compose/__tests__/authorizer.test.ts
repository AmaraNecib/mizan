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
    const source: Source<object> = {
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
    const source: Source<{ userId: string; tenantId: string }> = {
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
    const source: Source<object> = {
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
