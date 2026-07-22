/**
 * Mizan — Authorization Decision Ledger
 *
 * Interactive demo with three principals:
 * - Super Admin: full cars access + manage-policy permission
 * - Admin: full cars access only
 * - Support: read/create/delete grants with deny override for delete
 *
 * Only Super Admin can modify the in-memory policy (checked through a
 * real Mizan "manage-policy" decision). Every protected action on the
 * cars table and every policy mutation goes through decide() first.
 *
 * State is persisted in localStorage so page refreshes don't lose data
 * as long as the server stays up.
 */

import { createMizan } from "@mizan/core";
import type {
  SourceResolver,
  ResolveContext,
  AuthorizationFact,
  AuthorizationResult,
  RecurringSchedule,
} from "@mizan/core";
import { MemoryAdapter, useMemoryAdapter } from "@mizan/memory";

// ─── Types ─────────────────────────────────────────────────────────────────

type PrincipalId = "super-admin" | "admin" | "support";
type PresentationMode = "disabled" | "hide";
type CarAction = "cars.read" | "cars.create" | "cars.update" | "cars.delete";

interface Car {
  id: number;
  make: string;
  model: string;
}

interface DecisionRecord {
  principal: PrincipalId;
  action: string;
  decision: "allow" | "deny";
  reason: string | null;
  timestamp: Date;
}

interface SavedState {
  cars: Car[];
  nextCarId: number;
  updateGrant: boolean;
  deleteDeny: boolean;
  scheduleEnabled: boolean;
  scheduleStartH: number;
  scheduleStartM: number;
  scheduleEndH: number;
  scheduleEndM: number;
  clockTime: string;
  principal: PrincipalId;
  mode: PresentationMode;
}

// ─── localStorage persistence ───────────────────────────────────────────────

const STORAGE_KEY = "mizan52.state";

function saveState(): void {
  const data: SavedState = {
    cars,
    nextCarId,
    updateGrant: policySource.hasFact("support", "cars.update", "grant"),
    deleteDeny: policySource.hasFact("support", "cars.delete", "deny"),
    scheduleEnabled,
    scheduleStartH,
    scheduleStartM,
    scheduleEndH,
    scheduleEndM,
    clockTime: clockTime.toISOString(),
    principal: currentPrincipal,
    mode: presentationMode,
  };
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch {
    /* storage full or unavailable — degrade silently */
  }
}

function loadSavedState(): SavedState | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as SavedState) : null;
  } catch {
    return null;
  }
}

// ─── ES2022-compatible findLastIndex ────────────────────────────────────────
// Array.prototype.findLastIndex is ES2023; this polyfill keeps target at ES2022.

function polyfillFindLastIndex<T>(
  arr: T[],
  predicate: (item: T, index: number) => boolean,
): number {
  for (let i = arr.length - 1; i >= 0; i--) {
    if (predicate(arr[i]!, i)) return i;
  }
  return -1;
}

// ─── Mutable policy source ─────────────────────────────────────────────────

class MutablePolicySource implements SourceResolver {
  private readonly factsByPrincipal = new Map<string, AuthorizationFact[]>();

  addFact(principalId: string, fact: AuthorizationFact): void {
    const facts = this.factsByPrincipal.get(principalId) ?? [];
    facts.push({ ...fact });
    this.factsByPrincipal.set(principalId, facts);
  }

  /** Remove the last fact whose permission matches (most recently added wins). */
  removeFact(principalId: string, permission: string): boolean {
    const facts = this.factsByPrincipal.get(principalId);
    if (!facts || facts.length === 0) return false;
    const idx = polyfillFindLastIndex(facts, (f) => f.permission === permission);
    if (idx === -1) return false;
    facts.splice(idx, 1);
    return true;
  }

  /** Remove ALL facts matching a permission for a given principal. */
  removeAllFacts(principalId: string, permission: string): void {
    const facts = this.factsByPrincipal.get(principalId);
    if (!facts || facts.length === 0) return;
    this.factsByPrincipal.set(
      principalId,
      facts.filter((f) => f.permission !== permission),
    );
  }

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

const adapter = new MemoryAdapter({
  roles: [
    {
      name: "super-admin",
      permissions: [
        { permission: "cars.*", effect: "grant" },
        { permission: "manage-policy", effect: "grant" },
      ],
    },
    {
      name: "admin",
      permissions: [
        { permission: "cars.read", effect: "grant" },
        { permission: "cars.create", effect: "grant" },
        { permission: "cars.update", effect: "grant" },
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
    { principalId: "super-admin", roleName: "super-admin" },
    { principalId: "admin", roleName: "admin" },
    { principalId: "support", roleName: "support" },
  ],
});

useMemoryAdapter(mizan, adapter);

// Policy source holds per-principal overrides managed through the editor.
const policySource = new MutablePolicySource();

function applyDefaultPolicyFacts(): void {
  policySource.addFact("support", { permission: "cars.delete", effect: "deny" });
  policySource.addFact("admin", {
    permission: "cars.delete",
    effect: "grant",
    schedule: makeWeekSchedule(9, 0, 17, 0),
  });
}

function restorePolicyFactsFromSaved(saved: SavedState): void {
  // Wipe dynamic facts for the two principals we manage.
  policySource.removeAllFacts("support", "cars.delete");
  policySource.removeAllFacts("support", "cars.update");
  policySource.removeAllFacts("admin", "cars.delete");

  if (saved.deleteDeny) {
    policySource.addFact("support", { permission: "cars.delete", effect: "deny" });
  }
  if (saved.updateGrant) {
    policySource.addFact("support", { permission: "cars.update", effect: "grant" });
  }
  if (saved.scheduleEnabled) {
    policySource.addFact("admin", {
      permission: "cars.delete",
      effect: "grant",
      schedule: makeWeekSchedule(
        saved.scheduleStartH, saved.scheduleStartM,
        saved.scheduleEndH, saved.scheduleEndM,
      ),
    });
  } else {
    policySource.addFact("admin", {
      permission: "cars.delete",
      effect: "grant",
    });
  }
}

mizan.registerSource("policy", policySource);

// ─── Evaluators ────────────────────────────────────────────────────────────

const evaluators: Record<PrincipalId, ReturnType<typeof mizan.forPrincipal>> = {
  "super-admin": mizan.forPrincipal("super-admin"),
  admin: mizan.forPrincipal("admin"),
  support: mizan.forPrincipal("support"),
};

function getEvaluator(id: PrincipalId) {
  return evaluators[id];
}

/**
 * Evaluate a permission against the demo evaluation clock, not the real
 * system clock. All UI-facing authorization checks must use this helper
 * so schedule-controlled permissions (e.g., Admin cars.delete) are
 * consistently evaluated at the demo clock time everywhere — sidebar,
 * table buttons, and actual action clicks.
 */
async function decideAt(permission: string): Promise<AuthorizationResult> {
  return getEvaluator(currentPrincipal).decide(permission, { at: clockTime });
}

async function safeDecideAt(perm: string): Promise<AuthorizationResult> {
  try {
    return await decideAt(perm);
  } catch {
    return { decision: "deny", reason: "contract-violation" };
  }
}

// ─── Application state ─────────────────────────────────────────────────────

let currentPrincipal: PrincipalId = "super-admin";
let presentationMode: PresentationMode = "disabled";
let lastDecision: DecisionRecord | null = null;

let scheduleEnabled = true;
let scheduleStartH = 9;
let scheduleStartM = 0;
let scheduleEndH = 17;
let scheduleEndM = 0;

const INITIAL_CLOCK = new Date("2024-06-17T10:00:00Z");
let clockTime = new Date(INITIAL_CLOCK);

// Car data — defaults, then potentially overwritten by saved state below.
const DEFAULT_CARS: Car[] = [
  { id: 1, make: "Toyota", model: "Camry" },
  { id: 2, make: "Honda", model: "Civic" },
  { id: 3, make: "Ford", model: "Focus" },
];
let cars: Car[] = [...DEFAULT_CARS];
let nextCarId = 4;

// ─── Restore persisted state ───────────────────────────────────────────────

const saved = loadSavedState();
if (saved && Array.isArray(saved.cars)) {
  cars = saved.cars;
  nextCarId = saved.nextCarId;
  currentPrincipal = saved.principal;
  presentationMode = saved.mode;
  scheduleEnabled = saved.scheduleEnabled;
  scheduleStartH = saved.scheduleStartH;
  scheduleStartM = saved.scheduleStartM;
  scheduleEndH = saved.scheduleEndH;
  scheduleEndM = saved.scheduleEndM;
  // Clamp persisted values to valid ranges (corrupted localStorage guard).
  scheduleStartH = Math.max(0, Math.min(23, scheduleStartH));
  scheduleStartM = Math.max(0, Math.min(59, scheduleStartM));
  scheduleEndH = Math.max(0, Math.min(23, scheduleEndH));
  scheduleEndM = Math.max(0, Math.min(59, scheduleEndM));
  clockTime = new Date(saved.clockTime);
  if (isNaN(clockTime.getTime())) {
    clockTime = new Date(INITIAL_CLOCK);
  }
  restorePolicyFactsFromSaved(saved);
} else {
  applyDefaultPolicyFacts();
}

// ─── DOM helpers ───────────────────────────────────────────────────────────

function byId<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Element #${id} not found`);
  return el as T;
}

// ─── Feedback ──────────────────────────────────────────────────────────────

let feedbackTimer: ReturnType<typeof setTimeout> | null = null;

function showFeedback(msg: string, type: "success" | "error" | "info" = "info"): void {
  const el = byId("feedback");
  el.textContent = msg;
  el.className = `feedback feedback-${type} visible`;
  if (feedbackTimer) clearTimeout(feedbackTimer);
  feedbackTimer = setTimeout(() => el.classList.remove("visible"), 3500);
}

// ─── Decision banner ───────────────────────────────────────────────────────

function showDecision(
  principal: PrincipalId,
  action: string,
  decision: "allow" | "deny",
  reason: string | null,
): void {
  lastDecision = { principal, action, decision, reason, timestamp: new Date() };
  updateDecisionBanner();
}

function clearDecision(): void {
  lastDecision = null;
  const strip = byId("current-decision");
  // Wipe all visible state so no stale actor/permission leaks through.
  strip.className = "decision-strip";
  strip.querySelector(".decision-actor-label")!.textContent = "";
  strip.querySelector(".decision-verb")!.textContent = "";
  strip.querySelector(".decision-outcome")!.textContent = "";
  strip.querySelector(".decision-reason")!.textContent = "";
  strip.hidden = true;
  const trace = byId("decision-trace");
  trace.innerHTML = `<p class="trace-placeholder">${formatPrincipal(currentPrincipal)} selected — attempt an action to see the decision trace.<\/p>`;
}

function updateDecisionBanner(): void {
  const strip = byId("current-decision");
  const labelEl = strip.querySelector(".decision-actor-label")!;
  const verbEl = strip.querySelector(".decision-verb")!;
  const outcomeEl = strip.querySelector(".decision-outcome")!;
  const reasonEl = strip.querySelector(".decision-reason")!;

  if (!lastDecision) {
    strip.hidden = true;
    return;
  }

  strip.hidden = false;
  const d = lastDecision;
  const isAllow = d.decision === "allow";
  strip.className = `decision-strip result-${d.decision}`;
  labelEl.textContent = formatPrincipal(d.principal);
  verbEl.textContent = `· ${d.action} →`;
  outcomeEl.textContent = isAllow ? "ALLOW" : "DENY";
  reasonEl.textContent = d.reason ? d.reason : "";
}

function formatPrincipal(id: PrincipalId): string {
  switch (id) {
    case "super-admin": return "Super Admin";
    case "admin": return "Admin";
    case "support": return "Support";
  }
}

// ─── Permission summary (sidebar) ────────────────────────────────────────

/** Evaluate every relevant permission for the current principal and render the sidebar list. */
async function renderPermissions(): Promise<void> {
  const list = byId<HTMLUListElement>("perm-summary");
  const perms = [
    "cars.read",
    "cars.create",
    "cars.update",
    "cars.delete",
    "manage-policy",
  ];
  const results = await Promise.all(
    perms.map(async (p) => {
      try {
        const r = await decideAt(p);
        return { permission: p, result: r };
      } catch {
        return { permission: p, result: { decision: "deny" as const, reason: "error" } };
      }
    }),
  );

  list.innerHTML = results
    .map(({ permission, result }) => {
      const isAllow = result.decision === "allow";
      const cls = isAllow ? "allow" : "deny";
      const badge = isAllow ? "✓" : `✗ ${result.reason ?? ""}`;
      return `<li class="perm-${cls}"><span class="perm-key">${permission}</span><span class="perm-badge ${cls}">${badge}</span></li>`;
    })
    .join("");
}

// ─── Decision trace ────────────────────────────────────────────────────────

function updateTrace(
  action: string,
  decision: "allow" | "deny",
  reason: string | null,
  details?: string[],
): void {
  const trace = byId("decision-trace");
  const entry = document.createElement("div");
  entry.className = "trace-entry";

  const isAllow = decision === "allow";

  const permSpan = document.createElement("span");
  permSpan.className = "trace-permission";
  permSpan.textContent = action;
  entry.appendChild(permSpan);

  const resultSpan = document.createElement("span");
  resultSpan.className = `trace-result trace-result--${decision}`;
  resultSpan.textContent = isAllow ? "✓ allow" : "✗ deny";
  entry.appendChild(resultSpan);

  if (reason) {
    const reasonSpan = document.createElement("span");
    reasonSpan.className = "trace-reason";
    reasonSpan.textContent = reason;
    entry.appendChild(reasonSpan);
  }

  if (details) {
    for (const d of details) {
      const detailDiv = document.createElement("div");
      detailDiv.className = "trace-detail";
      detailDiv.textContent = d;
      entry.appendChild(detailDiv);
    }
  }

  trace.prepend(entry);
  while (trace.children.length > 8) {
    trace.lastElementChild?.remove();
  }
}

// ─── Protected action path (cars table) ────────────────────────────────────

async function attemptAction(action: CarAction, onAllowed: () => void): Promise<void> {
  try {
    const result = await decideAt(action);
    showDecision(currentPrincipal, action, result.decision, result.reason);

    if (result.decision === "allow") {
      onAllowed();
      showFeedback(`"${action}" → allowed`, "success");
      updateTrace(action, "allow", null, [
        `Principal: ${formatPrincipal(currentPrincipal)}`,
        "Grant from role or policy source matched.",
      ]);
    } else {
      const reason = result.reason ?? "unknown";
      showFeedback(`"${action}" → denied (${reason})`, "error");
      updateTrace(action, "deny", reason, [
        `Principal: ${formatPrincipal(currentPrincipal)}`,
        `Denial reason: ${reason}.`,
      ]);
    }
  } catch {
    showFeedback(`${action} check failed`, "error");
  }
  await renderTable();
}

// ─── Protected management path ─────────────────────────────────────────────

async function attemptManagement(
  onAllowed: () => void,
  label: string = "Policy change",
): Promise<boolean> {
  try {
    const result = await decideAt("manage-policy");
    showDecision(currentPrincipal, "manage-policy", result.decision, result.reason);

    if (result.decision === "allow") {
      onAllowed();
      showFeedback("Policy change applied → re-evaluated", "success");
      updateTrace("manage-policy", "allow", null, [`${label} — granted.`]);
      saveState();
      return true;
    } else {
      showFeedback("Policy management denied — only Super Admin can manage policy", "error");
      updateTrace("manage-policy", "deny", result.reason ?? "no-grant", [`${label} — blocked.`]);
      return false;
    }
  } catch {
    showFeedback("Policy check failed", "error");
    return false;
  }
}

// ─── Render cars table ─────────────────────────────────────────────────────

async function renderTable(): Promise<void> {
  const tbody = byId<HTMLTableSectionElement>("cars-tbody");

  const [readResult, updateResult, deleteResult] = await Promise.all([
    safeDecideAt("cars.read"),
    safeDecideAt("cars.update"),
    safeDecideAt("cars.delete"),
  ]);

  tbody.innerHTML = "";

  for (const car of cars) {
    const tr = document.createElement("tr");
    tr.dataset.carId = String(car.id);
    appendTd(tr, String(car.id));
    appendTd(tr, car.make);
    const modelTd = document.createElement("td");
    modelTd.className = "model-cell";
    modelTd.textContent = car.model;
    tr.appendChild(modelTd);

    const actionsTd = document.createElement("td");
    actionsTd.className = "actions-cell";

    addActionBtn(actionsTd, "Read", readResult, () =>
      attemptAction("cars.read", () =>
        showFeedback(`Car #${car.id}: ${car.make} ${car.model}`, "info"),
      ),
    );
    addActionBtn(actionsTd, "Update", updateResult, () =>
      attemptAction("cars.update", () => {
        closeActiveEditor();
        activeEditor = car.id;
        renderTable();
      }),
    );
    addActionBtn(actionsTd, "Delete", deleteResult, () =>
      attemptAction("cars.delete", () => {
        cars = cars.filter((c) => c.id !== car.id);
        showFeedback(`Car #${car.id} deleted`, "success");
        saveState();
        renderTable();
      }),
    );

    tr.appendChild(actionsTd);
    tbody.appendChild(tr);

    // If this car is being edited, render the update editor row directly below.
    if (activeEditor === car.id) {
      tbody.appendChild(buildUpdateEditorRow(car));
    }
  }

  const createResult = await safeDecideAt("cars.create");
  const createBtn = byId<HTMLButtonElement>("create-car-btn");
  if (createResult.decision === "allow") {
    createBtn.removeAttribute("disabled");
  } else {
    createBtn.disabled = true;
  }
}

function appendTd(tr: HTMLTableRowElement, text: string): void {
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

// ─── Principal switching ───────────────────────────────────────────────────

function syncScheduleUI(): void {
  const isSuper = currentPrincipal === "super-admin";
  byId<HTMLInputElement>("toggle-schedule").disabled = !isSuper;
  byId<HTMLInputElement>("schedule-start-h").disabled = !isSuper;
  byId<HTMLInputElement>("schedule-start-m").disabled = !isSuper;
  byId<HTMLInputElement>("schedule-end-h").disabled = !isSuper;
  byId<HTMLInputElement>("schedule-end-m").disabled = !isSuper;
  byId<HTMLButtonElement>("clock-dec").disabled = !isSuper;
  byId<HTMLButtonElement>("clock-inc").disabled = !isSuper;
  byId<HTMLButtonElement>("clock-reset").disabled = !isSuper;
}

async function setPrincipal(id: PrincipalId): Promise<void> {
  currentPrincipal = id;

  document.querySelectorAll<HTMLButtonElement>(".segmented-btn[data-principal]").forEach((btn) => {
    const isActive = btn.dataset.principal === id;
    btn.setAttribute("aria-checked", String(isActive));
    btn.classList.toggle("active", isActive);
  });

  const isSuper = id === "super-admin";
  byId("policy-super-admin").hidden = !isSuper;
  byId("policy-locked").hidden = isSuper;

  // Schedule bar is visible to all principals (so everyone sees the status)
  // but only Super Admin can interact with the controls.
  byId("schedule-bar").hidden = false;
  syncScheduleUI();

  document.querySelectorAll<HTMLSpanElement>(".actor-name").forEach((el) => {
    el.style.display = el.dataset.actor === id ? "inline" : "none";
  });

  closeActiveEditor();
  clearDecision();
  syncPolicyUI();
  await Promise.all([
    renderPermissions(),
    renderTable(),
  ]);
}

// ─── Policy UI sync ────────────────────────────────────────────────────────

function syncPolicyUI(): void {
  byId<HTMLInputElement>("toggle-update-grant").checked =
    policySource.hasFact("support", "cars.update", "grant");
  byId<HTMLInputElement>("toggle-delete-deny").checked =
    policySource.hasFact("support", "cars.delete", "deny");
}

// ─── Policy toggle handlers (protected by management check) ─────────────────

function setupPolicyToggles(): void {
  byId<HTMLInputElement>("toggle-update-grant").addEventListener("change", async (e) => {
    const checked = (e.target as HTMLInputElement).checked;
    const granted = await attemptManagement(() => {
      if (checked) {
        policySource.addFact("support", { permission: "cars.update", effect: "grant" });
      } else {
        policySource.removeFact("support", "cars.update");
      }
    }, `Toggle cars.update grant: ${checked ? "add" : "remove"}`);
    if (!granted) {
      byId<HTMLInputElement>("toggle-update-grant").checked = !checked;
    }
    await renderTable();
    renderPermissions();
    saveState();
  });

  byId<HTMLInputElement>("toggle-delete-deny").addEventListener("change", async (e) => {
    const checked = (e.target as HTMLInputElement).checked;
    const granted = await attemptManagement(() => {
      if (checked) {
        policySource.addFact("support", { permission: "cars.delete", effect: "deny" });
      } else {
        policySource.removeFact("support", "cars.delete");
      }
    }, `Toggle cars.delete deny: ${checked ? "add" : "remove"}`);
    if (!granted) {
      byId<HTMLInputElement>("toggle-delete-deny").checked = !checked;
    }
    await renderTable();
    renderPermissions();
    saveState();
  });
}

// ─── Schedule helpers ───────────────────────────────────────────────────────

function makeWeekSchedule(sh: number, sm: number, eh: number, em: number): RecurringSchedule {
  const start = `${String(sh).padStart(2, "0")}:${String(sm).padStart(2, "0")}`;
  const end = `${String(eh).padStart(2, "0")}:${String(em).padStart(2, "0")}`;
  const times = [{ start, end }];
  return {
    timezone: "UTC",
    weeks: [
      { day: "monday", times },
      { day: "tuesday", times },
      { day: "wednesday", times },
      { day: "thursday", times },
      { day: "friday", times },
    ],
  };
}

function updateClockDisplay(): void {
  const display = byId("clock-display");
  display.textContent = clockTime.toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

/**
 * Replace the schedule-controlled facts with ones matching the current controls,
 * then display the result for Admin's cars.delete.
 */
async function evaluateSchedule(): Promise<void> {
  policySource.removeAllFacts("admin", "cars.delete");

  if (scheduleEnabled) {
    policySource.addFact("admin", {
      permission: "cars.delete",
      effect: "grant",
      schedule: makeWeekSchedule(scheduleStartH, scheduleStartM, scheduleEndH, scheduleEndM),
    });
  } else {
    policySource.addFact("admin", {
      permission: "cars.delete",
      effect: "grant",
    });
  }

  try {
    const result = await getEvaluator("admin").decide("cars.delete", { at: clockTime });
    const el = byId("schedule-result");
    const isAllow = result.decision === "allow";
    el.innerHTML = `<div class="${isAllow ? "allow" : "deny"}">${
      isAllow
        ? scheduleEnabled
          ? "✓ cars.delete (Admin) — inside schedule"
          : "✓ cars.delete (Admin) — no restriction"
        : `✗ cars.delete (Admin) — ${result.reason ?? "unknown"}`
    }</div>`;
    el.className = "schedule-result";

    await Promise.all([
      renderTable(),
      renderPermissions(),
    ]);
  } catch {
    byId("schedule-result").innerHTML = "<div>Error evaluating schedule</div>";
  }
}

function setupScheduleControls(): void {
  const toggle = byId<HTMLInputElement>("toggle-schedule");
  toggle.addEventListener("change", async () => {
    const checked = toggle.checked;
    const granted = await attemptManagement(() => {
      scheduleEnabled = checked;
    }, `Toggle schedule: ${checked ? "enable" : "disable"}`);
    if (!granted) {
      toggle.checked = !checked;
      return;
    }
    await evaluateSchedule();
    saveState();
  });

  const setupHourInput = (id: string, setter: (v: number) => void): void => {
    const input = byId<HTMLInputElement>(id);
    input.addEventListener("change", async () => {
      const val = Number(input.value);
      if (isNaN(val)) return;
      const max = input.classList.contains("minute") ? 59 : 23;
      input.value = String(Math.max(0, Math.min(max, val)));

      const granted = await attemptManagement(() => {
        setter(Number(input.value));
      }, "Adjust schedule hours");
      if (!granted) {
        const isHour = !input.classList.contains("minute");
        input.value = String(
          id.includes("start")
            ? (isHour ? scheduleStartH : scheduleStartM)
            : (isHour ? scheduleEndH : scheduleEndM),
        );
        return;
      }
      await evaluateSchedule();
      saveState();
    });
  };

  setupHourInput("schedule-start-h", (v) => { scheduleStartH = v; });
  setupHourInput("schedule-start-m", (v) => { scheduleStartM = v; });
  setupHourInput("schedule-end-h", (v) => { scheduleEndH = v; });
  setupHourInput("schedule-end-m", (v) => { scheduleEndM = v; });

  byId("clock-inc").addEventListener("click", async () => {
    const granted = await attemptManagement(() => {
      clockTime = new Date(clockTime.getTime() + 3_600_000);
    }, "Advance clock");
    if (!granted) return;
    updateClockDisplay();
    await evaluateSchedule();
    saveState();
  });

  byId("clock-dec").addEventListener("click", async () => {
    const granted = await attemptManagement(() => {
      clockTime = new Date(clockTime.getTime() - 3_600_000);
    }, "Rewind clock");
    if (!granted) return;
    updateClockDisplay();
    await evaluateSchedule();
    saveState();
  });

  byId("clock-reset").addEventListener("click", async () => {
    const granted = await attemptManagement(() => {
      clockTime = new Date(INITIAL_CLOCK);
    }, "Reset clock");
    if (!granted) return;
    updateClockDisplay();
    await evaluateSchedule();
    saveState();
  });
}

// ─── Inline create form ────────────────────────────────────────────────────

let activeEditor: "create" | number | null = null;

function closeActiveEditor(): void {
  if (activeEditor === "create") {
    byId("create-form").hidden = true;
  }
  activeEditor = null;
}

function showCreateForm(): void {
  if (activeEditor !== null) closeActiveEditor();
  activeEditor = "create";
  byId("create-form").hidden = false;
  byId<HTMLInputElement>("create-make").value = "";
  byId<HTMLInputElement>("create-model").value = "";
  byId<HTMLInputElement>("create-make").focus();
}

function hideCreateForm(): void {
  byId("create-form").hidden = true;
  if (activeEditor === "create") activeEditor = null;
}

function setupCreateForm(): void {
  byId<HTMLButtonElement>("create-car-btn").addEventListener("click", async () => {
    const result = await decideAt("cars.create");
    if (result.decision === "allow") {
      showCreateForm();
    } else {
      showDecision(currentPrincipal, "cars.create", result.decision, result.reason);
      showFeedback("cars.create denied", "error");
    }
  });

  byId<HTMLButtonElement>("create-save").addEventListener("click", async () => {
    const make = byId<HTMLInputElement>("create-make").value.trim();
    const model = byId<HTMLInputElement>("create-model").value.trim();
    if (!make || !model) return;
    hideCreateForm();
    await attemptAction("cars.create", () => {
      cars.push({ id: nextCarId++, make, model });
      saveState();
    });
  });

  byId<HTMLButtonElement>("create-cancel").addEventListener("click", hideCreateForm);

  byId<HTMLInputElement>("create-model").addEventListener("keydown", (e) => {
    if (e.key === "Enter") byId<HTMLButtonElement>("create-save").click();
    if (e.key === "Escape") hideCreateForm();
  });
  byId<HTMLInputElement>("create-make").addEventListener("keydown", (e) => {
    if (e.key === "Escape") hideCreateForm();
  });
}

// ─── Update editor row (rendered deterministically inside renderTable) ────

function buildUpdateEditorRow(car: Car): HTMLTableRowElement {
  const row = document.createElement("tr");
  row.className = "update-editor-row";

  const mkInput = (val: string, label: string) => {
    const inp = document.createElement("input");
    inp.type = "text";
    inp.className = "inline-input";
    inp.value = val;
    inp.setAttribute("aria-label", label);
    return inp;
  };

  const makeInput = mkInput(car.make, "Car make");
  const modelInput = mkInput(car.model, "Car model");

  const saveBtn = document.createElement("button");
  saveBtn.className = "inline-btn inline-btn--primary";
  saveBtn.textContent = "Save";

  const cancelBtn = document.createElement("button");
  cancelBtn.className = "inline-btn";
  cancelBtn.textContent = "Cancel";

  const finish = async (save: boolean) => {
    if (save) {
      const newMake = makeInput.value.trim();
      const newModel = modelInput.value.trim();
      if (!newMake || !newModel) {
        showFeedback("Make and model cannot be empty", "error");
        return;
      }
      // Re-check authorization before mutating.
      const result = await decideAt("cars.update");
      if (result.decision !== "allow") {
        showDecision(currentPrincipal, "cars.update", result.decision, result.reason);
        showFeedback("cars.update no longer allowed", "error");
        activeEditor = null;
        renderTable();
        return;
      }
      car.make = newMake;
      car.model = newModel;
      showFeedback(`Car #${car.id} updated`, "success");
      saveState();
    }
    activeEditor = null;
    renderTable();
  };

  saveBtn.addEventListener("click", () => finish(true));
  cancelBtn.addEventListener("click", () => finish(false));
  makeInput.addEventListener("keydown", (e) => { if (e.key === "Escape") finish(false); });
  modelInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") finish(true);
    if (e.key === "Escape") finish(false);
  });

  // ID cell (empty)
  row.appendChild(document.createElement("td"));
  // Make cell
  const makeTd = document.createElement("td");
  makeTd.appendChild(makeInput);
  row.appendChild(makeTd);
  // Model cell
  const modelTd = document.createElement("td");
  modelTd.appendChild(modelInput);
  row.appendChild(modelTd);
  // Actions cell
  const actionsTd = document.createElement("td");
  actionsTd.appendChild(saveBtn);
  actionsTd.appendChild(document.createTextNode(" "));
  actionsTd.appendChild(cancelBtn);
  row.appendChild(actionsTd);

  // Focus the first field after render.
  requestAnimationFrame(() => makeInput.focus());

  return row;
}

// ─── Bootstrap ─────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll<HTMLButtonElement>("[data-principal]").forEach((btn) => {
    btn.addEventListener("click", () => {
      setPrincipal(btn.dataset.principal as PrincipalId);
      saveState();
    });
  });

  document.querySelectorAll<HTMLButtonElement>("[data-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      presentationMode = btn.dataset.mode as PresentationMode;
      document.querySelectorAll<HTMLButtonElement>("[data-mode]").forEach((b) => {
        const isActive = b.dataset.mode === presentationMode;
        b.setAttribute("aria-checked", String(isActive));
      });
      renderTable();
      saveState();
    });
  });

  setupCreateForm();

  byId<HTMLButtonElement>("reset-demo-btn").addEventListener("click", () => {
    try { localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
    location.reload();
  });

  setupPolicyToggles();
  setupScheduleControls();

  setPrincipal(currentPrincipal);
  updateClockDisplay();
  evaluateSchedule();
  // Decision strip starts hidden — no stale state.
});
