import { describe, test, expect } from "bun:test";
describe("docker-ip-whitelist", () => {
  test("module loads", async () => { const m = await import("./index"); expect(m).toBeDefined(); });
});
