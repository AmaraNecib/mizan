import assert from "node:assert/strict";
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
  const evaluateFacts = (scheduleFacts, hour = 10) => evaluate({
    action: "files.read",
    at: Date.UTC(2024, 0, 1, hour),
    snapshot: { knownActions: ["files.read"], facts: scheduleFacts },
  });

  const sameZoneFacts = facts(Array(100).fill("UTC"));
  assert.equal(evaluateFacts(sameZoneFacts, 9).outcome, "allow");
  assert.equal(evaluateFacts(sameZoneFacts, 17).code, "no-applicable-grant");
  const afterSameZone = constructions;
  assert.equal(evaluateFacts(sameZoneFacts).outcome, "allow");
  const afterRepeat = constructions;
  assert.equal(evaluateFacts(facts(["America/New_York", "America/New_York"])).code, "no-applicable-grant");
  const afterSecondZone = constructions;

  const supportedZones = Intl.supportedValuesOf("timeZone").slice(0, 101);
  assert.equal(evaluateFacts(facts(supportedZones, "other.read")).code, "no-applicable-grant");
  const afterEvictionSet = constructions;
  assert.equal(evaluateFacts(facts(["UTC"]), 9).outcome, "allow");
  assert.equal(evaluateFacts(facts(["UTC"]), 17).code, "no-applicable-grant");
  const afterEvictedUtc = constructions;
  results = { afterSameZone, afterRepeat, afterSecondZone, afterEvictionSet, afterEvictedUtc };
} finally {
  Intl.DateTimeFormat = OriginalDateTimeFormat;
}
console.log(JSON.stringify(results));
