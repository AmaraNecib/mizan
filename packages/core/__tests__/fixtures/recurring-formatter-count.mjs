import { evaluate } from "@mizan/core";

const OriginalDateTimeFormat = Intl.DateTimeFormat;
let constructions = 0;
Intl.DateTimeFormat = class extends OriginalDateTimeFormat {
  constructor(...args) {
    constructions += 1;
    super(...args);
  }
};

let results;
try {
  const facts = (timezones, permission = "files.read") => timezones.map((timezone) => ({
    permission,
    effect: "grant",
    schedules: [{
      timezone,
      weeks: [{ day: "monday", times: [{ start: "09:00", end: "17:00" }] }],
    }],
  }));
  const evaluateFacts = (scheduleFacts) => evaluate({
    action: "files.read",
    at: Date.UTC(2024, 0, 1, 10),
    snapshot: { knownActions: ["files.read"], facts: scheduleFacts },
  });

  const sameZoneFacts = facts(Array(100).fill("UTC"));
  evaluateFacts(sameZoneFacts);
  const afterSameZone = constructions;
  evaluateFacts(sameZoneFacts);
  const afterRepeat = constructions;
  evaluateFacts(facts(["America/New_York", "America/New_York"]));
  const afterSecondZone = constructions;

  const supportedZones = Intl.supportedValuesOf("timeZone").slice(0, 101);
  evaluateFacts(facts(supportedZones, "other.read"));
  const afterEvictionSet = constructions;
  evaluateFacts(facts(["UTC"]));
  const afterEvictedUtc = constructions;
  results = { afterSameZone, afterRepeat, afterSecondZone, afterEvictionSet, afterEvictedUtc };
} finally {
  Intl.DateTimeFormat = OriginalDateTimeFormat;
}
console.log(JSON.stringify(results));
