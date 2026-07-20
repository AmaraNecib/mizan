/**
 * Mizan — Interactive Authorization Decision Gallery
 *
 * An interactive playground around a small cars table. The viewer switches
 * the active principal between Admin and Support, changes demo-only
 * in-memory policy state for Support, and immediately sees how the same
 * protected actions resolve differently.
 *
 * Every protected action performs the real Mizan check before mutating
 * the table. The UI never duplicates authorization evaluation logic.
 */

import { createMizan } from "@mizan/core";
import type {
  SourceResolver,
  ResolveContext,
  AuthorizationFact,
  AuthorizationResult,
} from "@mizan/core";
import { MemoryAdapter, useMemoryAdapter } from "@mizan/memory";

// ─── Types ─────────────────────────────────────────────────────────────────

type PrincipalId = "admin" | "support";
type PresentationMode = "disabled" | "hide";
type CarAction = "cars.read" | "cars.create" | "cars.update" | "cars.delete";

interface Car {
  id: number;
  make: string;
  model: string;
}

// ─── Car data (demo-only, in-memory) ────────────────────────────────────────

let cars: Car[] = [
  { id: 1, make: "Toyota", model: "Camry" },
  { id: 2, make: "Honda", model: "Civic" },
  { id: 3, make: "Ford", model: "Focus" },
];
let nextCarId = 4;

// ─── Mutable policy source ─────────────────────────────────────────────────
// This source lets the demo UI add / remove facts in real time so the viewer
// can see how Mizan re-evaluates after every policy change.

class MutablePolicySource implements SourceResolver {
  private readonly factsByPrincipal = new Map<string, AuthorizationFact[]>();

  /** Add a fact for a given principal. Duplicate permissions are allowed. */
  addFact(principalId: string, fact: AuthorizationFact): void {
    const facts = this.factsByPrincipal.get(principalId) ?? [];
    facts.push({ ...fact });
    this.factsByPrincipal.set(principalId, facts);
  }

  /** Remove the last fact matching permission (and optionally effect). */
  removeFact(principalId: string, permission: string): boolean {
    const facts = this.factsByPrincipal.get(principalId);
    if (!facts || facts.length === 0) return false;
    const idx = facts.findLastIndex((f) => f.permission === permission);
    if (idx === -1) return false;
    facts.splice(idx, 1);
    return true;
  }

  /** Check whether a fact with the given permission (and optional effect) exists. */
  hasFact(principalId: string, permission: string, effect?: "grant" | "deny"): boolean {
    return (this.factsByPrincipal.get(principalId) ?? []).some(
      (f) => f.permission === permission && (effect === undefined || f.effect === effect),
    );
  }

  async resolve(context: ResolveContext): Promise<{
    status: "facts" | "miss";
    facts: AuthorizationFact[];
    freshness: "fresh";
  }> {
    const facts = this.factsByPrincipal.get(context.principalId) ?? [];
    if (facts.length === 0) return { status: "miss", facts: [], freshness: "fresh" };
    return { status: "facts", facts, freshness: "fresh" };
  }
}

// ─── Set up Mizan ──────────────────────────────────────────────────────────

const mizan = createMizan();

// Admin role: full cars namespace access.
// Support role: read, create, and delete grants (delete overridden by deny source).
const adapter = new MemoryAdapter({
  roles: [
    {
      name: "admin",
      permissions: [
        { permission: "cars.*", effect: "grant" },
        {
          permission: "reports.read",
          effect: "grant",
          schedule: {
            timezone: "UTC",
            weeks: [
              { day: "monday", times: [{ start: "09:00", end: "17:00" }] },
              { day: "tuesday", times: [{ start: "09:00", end: "17:00" }] },
              { day: "wednesday", times: [{ start: "09:00", end: "17:00" }] },
              { day: "thursday", times: [{ start: "09:00", end: "17:00" }] },
              { day: "friday", times: [{ start: "09:00", end: "17:00" }] },
            ],
          },
        },
      ],
    },
    {
      name: "support",
      permissions: [
        { permission: "cars.read", effect: "grant" },
        { permission: "cars.create", effect: "grant" },
        { permission: "cars.delete", effect: "grant" },
      ],
    },
  ],
  assignments: [
    { principalId: "admin", roleName: "admin" },
    { principalId: "support", roleName: "support" },
  ],
});

useMemoryAdapter(mizan, adapter);

// Mutable source for demo policy controls.
const policySource = new MutablePolicySource();
// Initial state: delete-deny override active for Support.
policySource.addFact("support", { permission: "cars.delete", effect: "deny" });

mizan.registerSource("policy", policySource);

// ─── Evaluators ────────────────────────────────────────────────────────────

const adminEval = mizan.forPrincipal("admin");
const supportEval = mizan.forPrincipal("support");

function getEvaluator(id: PrincipalId) {
  return id === "admin" ? adminEval : supportEval;
}

// ─── Application state ─────────────────────────────────────────────────────

let currentPrincipal: PrincipalId = "admin";
let presentationMode: PresentationMode = "disabled";

// ─── DOM helpers ───────────────────────────────────────────────────────────

function byId<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Element #${id} not found`);
  return el as T;
}

function qs<T extends Element>(parent: Element, sel: string): T | null {
  return parent.querySelector<T>(sel);
}

// ─── Feedback toast ────────────────────────────────────────────────────────

let feedbackTimeout: ReturnType<typeof setTimeout> | null = null;

function showFeedback(message: string, type: "success" | "error" | "info" = "info"): void {
  const el = byId<HTMLDivElement>("feedback");
  el.textContent = message;
  el.className = `feedback feedback-${type} visible`;
  if (feedbackTimeout) clearTimeout(feedbackTimeout);
  feedbackTimeout = setTimeout(() => {
    el.classList.remove("visible");
  }, 3500);
}

// ─── Protected action path ─────────────────────────────────────────────────
// Always performs the real Mizan check before mutating the table.

async function attemptAction(action: CarAction, onAllowed: () => void): Promise<void> {
  const evaluator = getEvaluator(currentPrincipal);
  try {
    const result = await evaluator.decide(action);
    if (result.decision === "allow") {
      onAllowed();
      showFeedback(`“${action}” → allowed ✓`, "success");
    } else {
      const reason = result.reason ?? "unknown";
      showFeedback(`“${action}” → denied ✗ (${reason})`, "error");
    }
  } catch (err) {
    showFeedback(`Error checking “${action}”: ${err}`, "error");
  }
  await renderTable();
}

// ─── Render cars table ─────────────────────────────────────────────────────

async function renderTable(): Promise<void> {
  const tbody = byId<HTMLTableSectionElement>("cars-tbody");

  // Batch-evaluate all row-level permissions.
  const [readResult, updateResult, deleteResult] = await Promise.all([
    safeDecide("cars.read"),
    safeDecide("cars.update"),
    safeDecide("cars.delete"),
  ]);

  tbody.innerHTML = "";

  for (const car of cars) {
    const tr = document.createElement("tr");
    tr.dataset.carId = String(car.id);

    appendCell(tr, String(car.id));
    appendCell(tr, car.make);
    appendCell(tr, car.model);

    // Actions cell
    const actionsTd = document.createElement("td");
    actionsTd.className = "actions-cell";

    addActionBtn(actionsTd, "Read", readResult, () =>
      attemptAction("cars.read", () => {
        showFeedback(`Car #${car.id}: ${car.make} ${car.model}`, "info");
      }),
    );

    addActionBtn(actionsTd, "Update", updateResult, () =>
      attemptAction("cars.update", () => {
        const newModel = prompt(`New model for “${car.make} ${car.model}”:`, car.model);
        if (newModel && newModel !== car.model) {
          car.model = newModel;
          showFeedback(`Car #${car.id} updated ✓`, "success");
          renderTable();
        }
      }),
    );

    addActionBtn(actionsTd, "Delete", deleteResult, () =>
      attemptAction("cars.delete", () => {
        cars = cars.filter((c) => c.id !== car.id);
        showFeedback(`Car #${car.id} deleted ✓`, "success");
        renderTable();
      }),
    );

    tr.appendChild(actionsTd);
    tbody.appendChild(tr);
  }

  // Update create button state.
  (await safeDecide("cars.create")).decision === "allow"
    ? byId<HTMLButtonElement>("create-car-btn").removeAttribute("disabled")
    : byId<HTMLButtonElement>("create-car-btn").setAttribute("disabled", "");

  // Update policy-effects panel.
  renderPolicyEffects();
}

function appendCell(tr: HTMLTableRowElement, text: string): void {
  const td = document.createElement("td");
  td.textContent = text;
  tr.appendChild(td);
}

function addActionBtn(
  container: HTMLElement,
  label: string,
  result: AuthorizationResult,
  onClick: () => void,
): void {
  const btn = document.createElement("button");
  btn.textContent = label;
  btn.className = "action-btn";

  if (result.decision === "deny") {
    btn.classList.add("action-btn--denied");
    btn.title = `Denied: ${result.reason ?? "unknown"}`;

    if (presentationMode === "hide") {
      btn.hidden = true;
    } else {
      btn.disabled = true;
      if (result.reason) {
        const badge = document.createElement("span");
        badge.className = "deny-reason";
        badge.textContent = result.reason;
        btn.appendChild(document.createTextNode(" "));
        btn.appendChild(badge);
      }
    }
  } else {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      onClick();
    });
  }

  container.appendChild(btn);
}

/** Call decide() and return a safe result even on error. */
async function safeDecide(perm: string): Promise<AuthorizationResult> {
  try {
    return await getEvaluator(currentPrincipal).decide(perm);
  } catch {
    return { decision: "deny", reason: "contract-violation" };
  }
}

// ─── Render policy-effects panel ───────────────────────────────────────────

function renderPolicyEffects(): void {
  const list = byId<HTMLUListElement>("effect-list");
  const principal = currentPrincipal;

  const items: string[] = [];

  // Always show role-derived baseline.
  if (principal === "admin") {
    items.push("Admin role grants <code>cars.*</code> → all actions allowed.");
  } else {
    items.push("Support role grants <code>cars.read</code>, <code>cars.create</code>, <code>cars.delete</code>.");
  }

  // Policy-source facts.
  if (policySource.hasFact("support", "cars.update", "grant")) {
    items.push("Policy source grants <code>cars.update</code> → update allowed.");
  } else if (principal === "support") {
    items.push("No grant for <code>cars.update</code> → denied (<code>no-grant</code>).");
  }

  if (policySource.hasFact("support", "cars.delete", "deny")) {
    items.push("Policy source denies <code>cars.delete</code> → override blocks delete (<code>matching-denial</code>).");
  } else if (principal === "support") {
    items.push("No deny override on <code>cars.delete</code> → role grant is effective (allowed).");
  }

  if (principal === "admin") {
    items.push("Policy controls affect Support only. Switch to Support to toggle.");
  }

  list.innerHTML = items
    .map((i) => `<li>${i}</li>`)
    .join("");
}

// ─── Principal switching ───────────────────────────────────────────────────

function setPrincipal(id: PrincipalId): void {
  currentPrincipal = id;

  // Update button active state.
  document.querySelectorAll<HTMLButtonElement>(".principal-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.principal === id);
  });

  // Show/hide policy controls.
  const policySection = byId<HTMLElement>("policy-controls");
  policySection.hidden = id !== "support";

  // Sync checkboxes to current policy state.
  const cbUpdate = byId<HTMLInputElement>("toggle-update-grant");
  const cbDelete = byId<HTMLInputElement>("toggle-delete-deny");
  cbUpdate.checked = policySource.hasFact("support", "cars.update", "grant");
  cbDelete.checked = policySource.hasFact("support", "cars.delete", "deny");

  renderTable();
}

// ─── Policy toggle handlers ────────────────────────────────────────────────

function setupPolicyToggles(): void {
  const cbUpdate = byId<HTMLInputElement>("toggle-update-grant");
  const cbDelete = byId<HTMLInputElement>("toggle-delete-deny");

  cbUpdate.addEventListener("change", () => {
    if (cbUpdate.checked) {
      policySource.addFact("support", { permission: "cars.update", effect: "grant" });
    } else {
      policySource.removeFact("support", "cars.update");
    }
    renderTable();
  });

  cbDelete.addEventListener("change", () => {
    if (cbDelete.checked) {
      policySource.addFact("support", { permission: "cars.delete", effect: "deny" });
    } else {
      policySource.removeFact("support", "cars.delete");
    }
    renderTable();
  });
}

// ─── Create car handler ────────────────────────────────────────────────────

async function onCreateCar(): Promise<void> {
  const make = prompt("Enter car make:");
  if (!make || make.trim() === "") return;
  const model = prompt("Enter car model:");
  if (!model || model.trim() === "") return;

  await attemptAction("cars.create", () => {
    cars.push({ id: nextCarId++, make: make.trim(), model: model.trim() });
  });
}

// ─── Schedule demo (evaluated once on load) ────────────────────────────────

async function renderScheduleDemo(): Promise<void> {
  const list = byId<HTMLUListElement>("schedule-results");
  const scenarios = [
    { label: "Monday 10:00 UTC", at: new Date("2024-06-17T10:00:00Z") },
    { label: "Sunday 10:00 UTC", at: new Date("2024-06-16T10:00:00Z") },
  ];

  // Admin has the scheduled permission.
  const evalAdmin = getEvaluator("admin");

  for (const s of scenarios) {
    const row = list.querySelector<HTMLLIElement>(`[data-label="${s.label}"]`);
    if (!row) continue;
    const badge = row.querySelector<HTMLElement>(".decision-badge");
    if (!badge) continue;

    row.classList.remove("loading");

    try {
      const result = await evalAdmin.decide("reports.read", { at: s.at });
      badge.className = "decision-badge";
      badge.classList.add(result.decision === "allow" ? "allow" : "deny");
      badge.innerHTML =
        result.decision === "allow"
          ? "✓ allow"
          : `✗ deny<span class="decision-badge reason">${result.reason ?? ""}</span>`;
    } catch (err) {
      badge.className = "decision-badge deny";
      badge.textContent = `✗ error`;
    }
  }
}

// ─── Bootstrap ─────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  // Principal switcher.
  document.querySelectorAll<HTMLButtonElement>(".principal-btn").forEach((btn) => {
    btn.addEventListener("click", () => setPrincipal(btn.dataset.principal as PrincipalId));
  });

  // Presentation-mode switcher.
  document.querySelectorAll<HTMLButtonElement>(".mode-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      presentationMode = btn.dataset.mode as PresentationMode;
      document.querySelectorAll<HTMLButtonElement>(".mode-btn").forEach((b) => {
        b.classList.toggle("active", b.dataset.mode === presentationMode);
      });
      renderTable();
    });
  });

  // Create car.
  byId<HTMLButtonElement>("create-car-btn").addEventListener("click", onCreateCar);

  // Policy toggles.
  setupPolicyToggles();

  // Render.
  setPrincipal("admin");
  renderScheduleDemo();
});
