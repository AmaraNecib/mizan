/**
 * @mizan/memory — In-memory adapter for Mizan authorization.
 *
 * Provides a reference implementation of the adapter contract using
 * in-memory storage. This is suitable for testing and single-process
 * applications. Production adapters may use databases, caches, or APIs.
 *
 * ## Design principles
 *
 * - **Reference implementation**: Follows the adapter contract as a
 *   canonical example for custom adapter authors.
 * - **Self-contained**: Depends only on `@mizan/core`. No database,
 *   ORM, or external service.
 * - **Ephemeral**: Data lives only as long as the process. This is
 *   intentional — the memory adapter is a development and testing tool.
 */

import type {
  AuthorizationFact,
  RoleDefinition,
  RoleAssignment,
  SourceOutcome,
  Mizan,
} from "@mizan/core";

// ─── Storage ───────────────────────────────────────────────────────────────

/**
 * In-memory storage for authorization data.
 *
 * Uses plain Maps for O(1) lookups. Not intended for multi-process
 * or persistent use.
 */
class MemoryStore {
  readonly permissions = new Map<string, AuthorizationFact[]>();
  readonly roles = new Map<string, RoleDefinition>();
  readonly assignments = new Map<string, RoleAssignment[]>();
  readonly directGrants = new Map<string, AuthorizationFact[]>();
  readonly directDenials = new Map<string, AuthorizationFact[]>();
}

// ─── Memory Adapter ────────────────────────────────────────────────────────

/**
 * Configuration for the memory adapter.
 */
export interface MemoryAdapterConfig {
  /** Initial permission facts to load. */
  facts?: AuthorizationFact[];
  /** Initial role definitions. */
  roles?: RoleDefinition[];
  /** Initial role assignments. */
  assignments?: RoleAssignment[];
}

/**
 * In-memory adapter that stores and serves authorization facts.
 *
 * This adapter exposes a single named source (`memory`) and is intended
 * as a reference for custom adapter authors.
 */
export class MemoryAdapter {
  private readonly store = new MemoryStore();

  constructor(config?: MemoryAdapterConfig) {
    if (config?.facts) {
      for (const fact of config.facts) {
        this.addFact(fact);
      }
    }
    if (config?.roles) {
      for (const role of config.roles) {
        this.store.roles.set(role.name, role);
      }
    }
    if (config?.assignments) {
      for (const assignment of config.assignments) {
        const existing = this.store.assignments.get(assignment.principalId) ?? [];
        existing.push(assignment);
        this.store.assignments.set(assignment.principalId, existing);
      }
    }
  }

  /**
   * Name of the default source exposed by this adapter.
   */
  readonly sourceName = "memory" as const;

  /**
   * Resolve authorization facts from the memory store.
   *
   * @param _context - Authorization context (unused in memory adapter).
   * @returns A source outcome with all stored facts.
   */
  async resolve(_context: { principalId?: string }): Promise<SourceOutcome> {
    const allFacts: AuthorizationFact[] = [];

    for (const facts of this.store.permissions.values()) {
      allFacts.push(...facts);
    }
    for (const facts of this.store.directGrants.values()) {
      allFacts.push(...facts);
    }
    for (const facts of this.store.directDenials.values()) {
      allFacts.push(...facts);
    }

    // Resolve role-derived grants
    if (_context.principalId) {
      const assigned = this.store.assignments.get(_context.principalId) ?? [];
      for (const assignment of assigned) {
        const role = this.store.roles.get(assignment.roleName);
        if (role) {
          allFacts.push(...role.permissions);
        }
      }
    }

    return {
      status: "facts",
      facts: allFacts,
      freshness: "fresh",
    };
  }

  // ─── Mutation helpers ────────────────────────────────────────────────────

  /**
   * Add a permission fact to the store.
   */
  addFact(fact: AuthorizationFact): void {
    const existing = this.store.permissions.get(fact.permission) ?? [];
    existing.push(fact);
    this.store.permissions.set(fact.permission, existing);
  }
}

/**
 * Connect the memory adapter to a Mizan instance.
 *
 * @param _mizan - The Mizan authorization instance.
 * @param _adapter - Configured memory adapter.
 *
 * TODO(#24): Implement adapter registration on Mizan
 */
export function useMemoryAdapter(_mizan: Mizan, _adapter: MemoryAdapter): void {
  // Placeholder — adapter registration will be implemented in #24
}
