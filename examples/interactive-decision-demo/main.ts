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
        // NOTE: reports.read is NOT in the role definition.
        // It lives solely in the mutable policy source so the schedule
        // editor is the single source of truth for that permission.
      ],
    },
    {
      name: "admin",
      permissions: [
        { permission: "cars.*", effect: "grant" },
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

// Policy source: Support overrides + sole reports.read.
const policySource = new MutablePolicySource();

function applyDefaultPolicyFacts(): void {
  policySource.addFact("support", { permission: "cars.delete", effect: "deny" });
  policySource.addFact("super-admin", {
    permission: "reports.read",
    effect: "grant",
    schedule: makeWeekSchedule(9, 0, 17, 0),
  });
}

function restorePolicyFactsFromSaved(saved: SavedState): void {
  // Wipe dynamic facts for the two principals we manage.
  policySource.removeAllFacts("support", "cars.delete");
  policySource.removeAllFacts("support", "cars.update");
  policySource.removeAllFacts("super-admin", "reports.read");

  if (saved.deleteDeny) {
    policySource.addFact("support", { permission: "cars.delete", effect: "deny" });
  }
  if (saved.updateGrant) {
    policySource.addFact("support", { permission: "cars.update", effect: "grant" });
  }
  if (saved.scheduleEnabled) {
    policySource.addFact("super-admin", {
      permission: "reports.read",
      effect: "grant",
      schedule: makeWeekSchedule(
        saved.scheduleStartH, saved.scheduleStartM,
        saved.scheduleEndH, saved.scheduleEndM,
      ),
    });
  } else {
    policySource.addFact("super-admin", {
      permission: "reports.read",
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

function updateDecisionBanner(): void {
  const banner = byId("current-decision");
  const labelEl = banner.querySelector(".decision-actor-label")!;
  const verbEl = banner.querySelector(".decision-verb")!;
  const outcomeEl = banner.querySelector(".decision-outcome")!;
  const reasonEl = banner.querySelector(".decision-reason")!;

  if (!lastDecision) {
    banner.className = "decision-banner idle";
    labelEl.textContent = "No decision yet";
    verbEl.textContent = "";
    outcomeEl.textContent = "";
    reasonEl.textContent = "";
    return;
  }

  const d = lastDecision;
  const isAllow = d.decision === "allow";
  banner.className = `decision-banner result-${d.decision}`;
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
  entry.innerHTML = `
    <span class="trace-permission">${action}</span>
    <span class="trace-result trace-result--${decision}">${isAllow ? "✓ allow" : "✗ deny"}</span>
    ${reason ? `<span class="trace-reason">${reason}</span>` : ""}
    ${details ? details.map((d) => `<div class="trace-detail">${d}</div>`).join("") : ""}
  `;

  trace.prepend(entry);
  while (trace.children.length > 8) {
    trace.lastElementChild?.remove();
  }
}

// ─── Protected action path (cars table) ────────────────────────────────────

async function attemptAction(action: CarAction, onAllowed: () => void): Promise<void> {
  const evaluator = getEvaluator(currentPrincipal);
  try {
    const result = await evaluator.decide(action);
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
  const evaluator = getEvaluator(currentPrincipal);
  try {
    const result = await evaluator.decide("manage-policy");
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
    safeDecide("cars.read"),
    safeDecide("cars.update"),
    safeDecide("cars.delete"),
  ]);

  tbody.innerHTML = "";

  for (const car of cars) {
    const tr = document.createElement("tr");
    appendTd(tr, String(car.id));
    appendTd(tr, car.make);
    appendTd(tr, car.model);

    const actionsTd = document.createElement("td");
    actionsTd.className = "actions-cell";

    addActionBtn(actionsTd, "Read", readResult, () =>
      attemptAction("cars.read", () =>
        showFeedback(`Car #${car.id}: ${car.make} ${car.model}`, "info"),
      ),
    );
    addActionBtn(actionsTd, "Update", updateResult, () =>
      attemptAction("cars.update", () => {
        const newModel = prompt(`New model for ${car.make} ${car.model}:`, car.model);
        if (newModel && newModel.trim()) {
          car.model = newModel.trim();
          showFeedback(`Car #${car.id} updated`, "success");
          saveState();
          renderTable();
        }
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
  }

  const createResult = await safeDecide("cars.create");
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

async function safeDecide(perm: string): Promise<AuthorizationResult> {
  try {
    return await getEvaluator(currentPrincipal).decide(perm);
  } catch {
    return { decision: "deny", reason: "contract-violation" };
  }
}

// ─── Principal switching ───────────────────────────────────────────────────

function setPrincipal(id: PrincipalId): void {
  currentPrincipal = id;

  document.querySelectorAll<HTMLButtonElement>(".segmented-btn[data-principal]").forEach((btn) => {
    const isActive = btn.dataset.principal === id;
    btn.setAttribute("aria-checked", String(isActive));
    btn.classList.toggle("active", isActive);
  });

  const isSuper = id === "super-admin";
  byId("policy-super-admin").hidden = !isSuper;
  byId("policy-locked").hidden = isSuper;

  document.querySelectorAll<HTMLSpanElement>(".actor-name").forEach((el) => {
    el.style.display = el.dataset.actor === id ? "inline" : "none";
  });

  syncPolicyUI();
  renderTable();
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
 * Replace the sole reports.read fact with one matching the current controls.
 * Because reports.read exists ONLY in the policy source (not in the role),
 * the editor is the single source of truth.
 */
async function evaluateSchedule(): Promise<void> {
  policySource.removeAllFacts("super-admin", "reports.read");

  if (scheduleEnabled) {
    policySource.addFact("super-admin", {
      permission: "reports.read",
      effect: "grant",
      schedule: makeWeekSchedule(scheduleStartH, scheduleStartM, scheduleEndH, scheduleEndM),
    });
  } else {
    policySource.addFact("super-admin", {
      permission: "reports.read",
      effect: "grant",
    });
  }

  const evalSA = getEvaluator("super-admin");
  try {
    const result = await evalSA.decide("reports.read", { at: clockTime });
    const el = byId("schedule-result");
    const isAllow = result.decision === "allow";
    el.className = `schedule-result ${isAllow ? "allow" : "deny"}`;
    el.textContent = isAllow
      ? scheduleEnabled
        ? "✓ reports.read allowed (inside schedule)"
        : "✓ reports.read allowed (no schedule restriction)"
      : `✗ reports.read denied (${result.reason ?? "unknown"})`;
  } catch {
    byId("schedule-result").textContent = "Error evaluating schedule";
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
    clockTime = new Date(clockTime.getTime() + 3_600_000);
    updateClockDisplay();
    await evaluateSchedule();
    saveState();
  });

  byId("clock-dec").addEventListener("click", async () => {
    clockTime = new Date(clockTime.getTime() - 3_600_000);
    updateClockDisplay();
    await evaluateSchedule();
    saveState();
  });

  byId("clock-reset").addEventListener("click", async () => {
    clockTime = new Date(INITIAL_CLOCK);
    updateClockDisplay();
    await evaluateSchedule();
    saveState();
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
    saveState();
  });
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

  byId<HTMLButtonElement>("create-car-btn").addEventListener("click", onCreateCar);

  setupPolicyToggles();
  setupScheduleControls();

  setPrincipal(currentPrincipal);
  updateClockDisplay();
  evaluateSchedule();
  updateDecisionBanner();
});
