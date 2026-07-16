import { describe, it, expect } from "bun:test";
import { createMizan, can, decide, Mizan } from "../src/index.ts";

describe("@mizan/core", () => {
  it("exports createMizan", () => {
    const mizan = createMizan();
    expect(mizan).toBeInstanceOf(Mizan);
  });

  it("exports can as a function", () => {
    expect(can).toBeInstanceOf(Function);
  });

  it("exports decide as a function", () => {
    expect(decide).toBeInstanceOf(Function);
  });

  it("can returns false by default (deny-by-default)", async () => {
    const result = await can("any.permission");
    expect(result).toBe(false);
  });

  it("decide returns deny with no-grant reason by default", async () => {
    const result = await decide("any.permission");
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("no-grant");
  });

  it("Mizan class can be instantiated", () => {
    const mizan = new Mizan();
    expect(mizan).toBeDefined();
    expect(mizan.constructor.name).toBe("Mizan");
  });
});
