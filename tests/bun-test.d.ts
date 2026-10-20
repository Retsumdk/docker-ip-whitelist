declare module "bun:test" {
  export interface Matchers<T> {
    toBe(expected: T): void;
    toEqual(expected: unknown): void;
    toBeGreaterThan(expected: number): void;
    toBeGreaterThanOrEqual(expected: number): void;
    toBeLessThan(expected: number): void;
    toContain(expected: unknown): void;
    toMatch(pattern: RegExp | string): void;
    toThrow(expected?: string | RegExp): void;
    toHaveLength(expected: number): void;
    toBeNull(): void;
    toBeDefined(): void;
    toBeUndefined(): void;
  }
  export function expect<T>(value: T): Matchers<T>;
  export function describe(name: string, fn: () => void): void;
  export function test(name: string, fn: () => void | Promise<void>): void;
}
