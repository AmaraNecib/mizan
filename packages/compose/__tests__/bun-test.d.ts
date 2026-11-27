// Local runner declarations keep test inputs checked without adding a runtime dependency.
declare module "bun:test" {
  type Constructor = abstract new (...args: never[]) => object;
  interface Matchers<Result> {
    toBe(expected: unknown): Result;
    toEqual(expected: unknown): Result;
    toMatchObject(expected: unknown): Result;
    toBeInstanceOf(expected: Constructor): Result;
    toThrow(expected?: Constructor | string | RegExp): Result;
  }
  interface Expectations extends Matchers<void> {
    readonly resolves: Matchers<Promise<void>>;
    readonly rejects: Matchers<Promise<void>>;
  }
  export function describe(name: string, fn: () => void): void;
  export function it(name: string, fn: () => void | Promise<void>): void;
  export function expect(value: unknown): Expectations;
}
