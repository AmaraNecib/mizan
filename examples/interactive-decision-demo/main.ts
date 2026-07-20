/**
 * Mizan — Interactive Authorization Decision Gallery
 *
 * This demo creates a Mizan authorization instance, wires up the memory
 * adapter (for role-based grants) and a second inline source (for a
 * principal-specific denial), then evaluates permissions for two
 * principals side by side.
 *
 * All authorization logic lives in @mizan/core and @mizan/memory.
 * The UI only asks questions and renders answers — it never duplicates
 * the decision logic.
 */

import { createMizan } from "@mizan/core";
import type { SourceResolver, ResolveContext } from "@mizan/core";
import { MemoryAdapter, useMemoryAdapter } from "@mizan/memory";

// ─── Set up the Mizan instance ─────────────────────────────────────────────

const mizan = createMizan();

// ─── Memory adapter: role definitions & assignments ─────────────────────────

const adapter = new MemoryAdapter({
  roles: [
    {
      name: "admin",
      permissions: [
        { permission: "cars.*", effect: "grant" },
        {
          permission: "schedules.read",
          effect: "grant",
          schedule: {
            timezone: "UTC",
            weeks: [
              {
                day: "monday",
                times: [{ start: "09:00", end: "17:00" }],
              },
              {
                day: "tuesday",
                times: [{ start: "09:00", end: "17:00" }],
              },
              {
                day: "wednesday",
                times: [{ start: "09:00", end: "17:00" }],
              },
              {
                day: "thursday",
                times: [{ start: "09:00", end: "17:00" }],
              },
              {
                day: "friday",
                times: [{ start: "09:00", end: "17:00" }],
              },
            ],
          },
        },
      ],
    },
    {
      name: "support",
      permissions: [
        { permission: "cars.read", effect: "grant" },
      ],
    },
  ],
  assignments: [
    { principalId: "admin", roleName: "admin" },
    { principalId: "support", roleName: "support" },
  ],
});

useMemoryAdapter(mizan, adapter);

// ─── Second source: principal-specific denial for Support ───────────────────
// This shows cross-source denial-overrides-grant: the memory adapter grants
// nothing for cars.delete, so the denial from this source is the final word.

const denialsSource: SourceResolver = {
  async resolve(context: ResolveContext): Promise<{
    status: "facts" | "miss";
    facts: { permission: string; effect: "deny" }[];
    freshness: "fresh";
  }> {
    if (context.principalId === "support") {
      return {
        status: "facts",
        facts: [{ permission: "cars.delete", effect: "deny" }],
        freshness: "fresh",
      };
    }
    return { status: "miss", facts: [], freshness: "fresh" };
  },
};

mizan.registerSource("denials", denialsSource);

// ─── Evaluators ────────────────────────────────────────────────────────────

const adminEval = mizan.forPrincipal("admin");
const supportEval = mizan.forPrincipal("support");

// ─── DOM helpers ───────────────────────────────────────────────────────────

function getById<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Element #${id} not found`);
  return el as T;
}

function renderDecision(
  badge: HTMLElement,
  result: { decision: string; reason: string | null },
): void {
  const badgeEl = badge;
  badgeEl.classList.remove("loading");

  if (result.decision === "allow") {
    badgeEl.className = "decision-badge allow";
    badgeEl.textContent = "✓ allow";
  } else {
    badgeEl.className = "decision-badge deny";
    badgeEl.textContent = `✗ deny`;
    if (result.reason) {
      const reasonSpan = document.createElement("span");
      reasonSpan.className = "decision-badge reason";
      reasonSpan.textContent = result.reason;
      badgeEl.appendChild(reasonSpan);
    }
  }
}

// ─── Evaluate role-based permissions ───────────────────────────────────────

async function evaluateRolePermissions(): Promise<void> {
  const permissions = ["cars.read", "cars.delete"];
  const principals: Array<{
    id: string;
    listId: string;
  }> = [
    { id: "admin", listId: "admin-results" },
    { id: "support", listId: "support-results" },
  ];

  for (const p of principals) {
    const list = getById<HTMLUListElement>(p.listId);
    const evaluator = p.id === "admin" ? adminEval : supportEval;

    for (const perm of permissions) {
      const row = list.querySelector(
        `[data-permission="${perm}"]`,
      ) as HTMLLIElement | null;
      if (!row) continue;

      const badge = row.querySelector(".decision-badge") as HTMLElement;
      if (!badge) continue;

      row.classList.remove("loading");

      try {
        const result = await evaluator.decide(perm);
        renderDecision(badge, result);
      } catch (err) {
        badge.className = "decision-badge deny";
        badge.textContent = `✗ error: ${err instanceof Error ? err.message : String(err)}`;
      }
    }
  }
}

// ─── Evaluate schedule scenario ────────────────────────────────────────────

async function evaluateScheduleScenario(): Promise<void> {
  const list = getById<HTMLUListElement>("schedule-results");
  const scenarios = [
    {
      label: "Monday 10:00 UTC",
      at: new Date("2024-06-17T10:00:00Z"),
    },
    {
      label: "Sunday 10:00 UTC",
      at: new Date("2024-06-16T10:00:00Z"),
    },
  ];

  for (const scenario of scenarios) {
    const row = list.querySelector(
      `[data-label="${scenario.label}"]`,
    ) as HTMLLIElement | null;
    if (!row) continue;

    const badge = row.querySelector(".decision-badge") as HTMLElement;
    if (!badge) continue;

    row.classList.remove("loading");

    try {
      const result = await adminEval.decide("schedules.read", {
        at: scenario.at,
      });
      renderDecision(badge, result);
    } catch (err) {
      badge.className = "decision-badge deny";
      badge.textContent = `✗ error: ${err instanceof Error ? err.message : String(err)}`;
    }
  }
}

// ─── Bootstrap ─────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  await Promise.all([evaluateRolePermissions(), evaluateScheduleScenario()]);
});
