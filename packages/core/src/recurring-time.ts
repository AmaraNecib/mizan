export type ActivityWindow = {
  readonly start: string;
  readonly end: string;
};
export type WeeklyActivityWindow = {
  readonly day: "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday" | "sunday";
  readonly times: readonly ActivityWindow[];
};
export type DateActivityWindow = {
  readonly date: string;
  readonly times: readonly ActivityWindow[];
};
export type ActivitySchedule = {
  readonly timezone: string;
  readonly weeks?: readonly WeeklyActivityWindow[];
  readonly dates?: readonly DateActivityWindow[];
};

type Fail = (message: string) => never;
type NormalizedSchedule = ActivitySchedule;

const days = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"] as const;
const dayIndex = new Map<string, number>(days.map((day, index) => [day, index]));

function record(value: unknown, fail: Fail, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(`${label} must be a plain data object`);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail(`${label} must be a plain data object`);
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== "string" || descriptor === undefined || !("value" in descriptor)) fail(`${label} must contain string-keyed data properties`);
    Object.defineProperty(result, key, { value: descriptor.value, enumerable: true });
  }
  return result;
}
function keys(value: Record<string, unknown>, allowed: readonly string[], fail: Fail, label: string): void {
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`${label} contains an unsupported field`);
}
function array(value: unknown, fail: Fail, label: string): unknown[] {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  const result: unknown[] = [];
  for (let i = 0; i < value.length; i += 1) {
    const d = Object.getOwnPropertyDescriptor(value, String(i));
    if (d === undefined || !("value" in d)) fail(`${label} must contain indexed data properties without holes`);
    result.push(d.value);
  }
  for (const key of Reflect.ownKeys(value)) {
    if (key === "length" || (typeof key === "string" && /^(0|[1-9]\d*)$/u.test(key) && Number(key) < value.length)) continue;
    fail(`${label} contains an unsupported property`);
  }
  return result;
}
function parseTime(value: unknown, fail: Fail, label: string): number {
  if (typeof value !== "string" || !/^(?:[01]\d|2[0-3]):[0-5]\d$/u.test(value)) fail(`${label} must be HH:mm`);
  return Number(value.slice(0, 2)) * 60 + Number(value.slice(3));
}
function normalizeTimes(value: unknown, fail: Fail, label: string): readonly ActivityWindow[] {
  return array(value, fail, label).map((entry) => {
    const item = record(entry, fail, label);
    keys(item, ["start", "end"], fail, label);
    const start = item.start;
    const end = item.end;
    parseTime(start, fail, label);
    parseTime(end, fail, label);
    return { start: start as string, end: end as string };
  });
}
function validDate(date: unknown, fail: Fail): string {
  if (typeof date !== "string" || !/^(\d{4})-(\d{2})-(\d{2})$/u.test(date)) fail("Schedule date must be YYYY-MM-DD");
  const [year = 0, month = 0, day = 0] = date.split("-").map(Number);
  if (year < 1 || year > 9999) fail("Schedule date must be within years 0001 through 9999");
  const check = new Date(0);
  check.setUTCHours(0, 0, 0, 0);
  check.setUTCFullYear(year, month - 1, day);
  if (check.getUTCFullYear() !== year || check.getUTCMonth() !== month - 1 || check.getUTCDate() !== day) fail("Schedule date is not a valid Gregorian date");
  return date;
}
export function normalizeSchedules(value: unknown, fail: Fail): readonly NormalizedSchedule[] | undefined {
  if (value === undefined) return undefined;
  return array(value, fail, "Fact schedules").map((entry) => {
    const schedule = record(entry, fail, "Activity schedule");
    keys(schedule, ["timezone", "weeks", "dates"], fail, "Activity schedule");
    if (typeof schedule.timezone !== "string" || schedule.timezone.length === 0 || /^(?:[+-]\d{2}(?::?\d{2})?|GMT[+-]|Etc\/GMT[+-])/u.test(schedule.timezone)) fail("Schedule timezone must be an IANA named zone");
    try { new Intl.DateTimeFormat("en-US", { timeZone: schedule.timezone, calendar: "gregory", numberingSystem: "latn", hourCycle: "h23" }); }
    catch { fail("Schedule timezone is not supported by this runtime"); }
    if (schedule.weeks === undefined && schedule.dates === undefined) fail("Activity schedule requires weeks or dates");
    const weeks = schedule.weeks === undefined ? [] : array(schedule.weeks, fail, "Schedule weeks").map((entry) => {
      const week = record(entry, fail, "Weekly window");
      keys(week, ["day", "times"], fail, "Weekly window");
      if (typeof week.day !== "string" || !dayIndex.has(week.day)) fail("Weekly window day is invalid");
      return { day: week.day as WeeklyActivityWindow["day"], times: normalizeTimes(week.times, fail, "Weekly times") };
    });
    const dates = schedule.dates === undefined ? [] : array(schedule.dates, fail, "Schedule dates").map((entry) => {
      const dated = record(entry, fail, "Date window");
      keys(dated, ["date", "times"], fail, "Date window");
      return { date: validDate(dated.date, fail), times: normalizeTimes(dated.times, fail, "Date times") };
    });
    return { timezone: schedule.timezone, weeks, dates };
  });
}

function dateParts(timestamp: number, timezone: string, fail: Fail): { year: number; month: number; day: number; weekday: number; minute: number } {
  let parts: Intl.DateTimeFormatPart[];
  try {
    parts = new Intl.DateTimeFormat("en-US-u-ca-gregory-nu-latn", { timeZone: timezone, era: "short", year: "numeric", month: "2-digit", day: "2-digit", weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(new Date(timestamp));
  } catch { return fail("Scheduled fact instant is outside the supported Date range"); }
  const get = (type: string) => parts.find((part) => part.type === type)?.value;
  // Intl uses era-relative years; Date arithmetic uses astronomical year zero.
  const eraYear = Number(get("year"));
  const year = get("era") === "BC" ? 1 - eraYear : eraYear;
  const month = Number(get("month")); const day = Number(get("day"));
  const hour = Number(get("hour")); const minute = Number(get("minute"));
  const weekday = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(get("weekday") ?? "");
  if (![year, month, day, hour, minute].every(Number.isFinite) || weekday < 0) return fail("Runtime returned an invalid local date-time");
  return { year, month, day, weekday, minute: hour * 60 + minute };
}
function previousDate(year: number, month: number, day: number): { year: number; month: number; day: number } {
  const date = new Date(0);
  date.setUTCHours(0, 0, 0, 0);
  date.setUTCFullYear(year, month - 1, day - 1);
  return { year: date.getUTCFullYear(), month: date.getUTCMonth() + 1, day: date.getUTCDate() };
}
function dateString(year: number, month: number, day: number): string {
  return `${String(year).padStart(4, "0")}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}
function timeMatches(times: readonly ActivityWindow[], minute: number, preceding: boolean): boolean {
  return times.some(({ start, end }) => {
    const from = Number(start.slice(0, 2)) * 60 + Number(start.slice(3));
    const to = Number(end.slice(0, 2)) * 60 + Number(end.slice(3));
    return from < to ? !preceding && minute >= from && minute < to
      : from > to && (preceding ? minute < to : minute >= from);
  });
}
export function scheduleMatches(schedules: readonly NormalizedSchedule[] | undefined, timestamp: number, fail: Fail): boolean {
  if (schedules === undefined || schedules.length === 0) return true;
  return schedules.every((schedule) => {
    const local = dateParts(timestamp, schedule.timezone, fail);
    const previous = previousDate(local.year, local.month, local.day);
    const currentDate = dateString(local.year, local.month, local.day);
    const priorDate = dateString(previous.year, previous.month, previous.day);
    const weekActive = (schedule.weeks ?? []).some((window) => {
      const anchor = dayIndex.get(window.day)!;
      const priorDay = (local.weekday + 6) % 7;
      return (anchor === local.weekday && timeMatches(window.times, local.minute, false))
        || (anchor === priorDay && timeMatches(window.times, local.minute, true));
    });
    const dateActive = (schedule.dates ?? []).some((window) =>
      (window.date === currentDate && timeMatches(window.times, local.minute, false))
      || (window.date === priorDate && timeMatches(window.times, local.minute, true))
    );
    return weekActive || dateActive;
  });
}
