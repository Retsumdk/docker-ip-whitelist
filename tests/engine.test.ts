import { describe, expect, test } from "bun:test";
import { rollback, shellRunner, sync } from "../src/engine.js";
import { STATE_FORMAT, loadState, saveState } from "../src/state.js";
import { Whitelist } from "../src/whitelist.js";
import { loadState as loadCorruptProbe } from "../src/state.js";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const tmp = () => mkdtempSync(join(tmpdir(), "diw-engine-"));
const fakeRun = () => async (cmd: string) => ({ ok: true, stdout: cmd, stderr: "" });

describe("shellRunner", () => {
  test("returns ok with stdout", async () => {
    const result = await shellRunner("echo hello");
    expect(result.ok).toBe(true);
    expect(result.stdout.trim()).toBe("hello");
  });

  test("captures failures", async () => {
    const result = await shellRunner("exit 3");
    expect(result.ok).toBe(false);
  });
});

describe("sync", () => {
  test("applies with the injected runner and saves state", async () => {
    const dir = tmp();
    const statePath = join(dir, "state.json");
    const wl = new Whitelist();
    wl.add("10.0.0.0/24", "203.0.113.7");

    const { report, plan } = await sync(wl, { statePath }, { run: fakeRun() });

    expect(report.applied).toBe(true);
    expect(report.dryRun).toBe(false);
    expect(report.ruleCount).toBe(2);
    expect(report.commandCount).toBe(4 + 2 + 1);
    expect(report.drifted).toBe(false);
    expect(report.changed).toBe(true);
    expect(report.previousRules).toBeNull();
    expect(report.outputs[0].command).toContain("iptables -N DOCKER-USER");
    expect(plan.rules).toEqual(["10.0.0.0/24", "203.0.113.7/32"]);

    const state = loadState(statePath);
    expect(state).not.toBeNull();
    expect(state!.format).toBe(STATE_FORMAT);
    expect(state!.rules).toEqual(["10.0.0.0/24", "203.0.113.7/32"]);
    expect(state!.defaultPolicy).toBe("drop");
    expect(state!.previous).toBeUndefined();
  });

  test("dry run executes nothing and writes no state", async () => {
    const dir = tmp();
    const statePath = join(dir, "state.json");
    const wl = new Whitelist();
    wl.add("10.0.0.0/24");

    let calls = 0;
    const { report } = await sync(wl, { statePath, dryRun: true }, {
      run: async (cmd) => {
        calls++;
        return { ok: true, stdout: cmd, stderr: "" };
      },
    });

    expect(calls).toBe(0);
    expect(report.applied).toBe(false);
    expect(report.dryRun).toBe(true);
    expect(report.outputs.every((o) => o.stdout === "(dry-run) not executed")).toBe(true);
    expect(loadState(statePath)).toBeNull();
  });

  test("second sync keeps the previous ruleset for rollback", async () => {
    const dir = tmp();
    const statePath = join(dir, "state.json");

    const first = new Whitelist();
    first.add("10.0.0.0/8");
    await sync(first, { statePath }, { run: fakeRun() });

    const second = new Whitelist();
    second.add("192.168.0.0/16");
    const { report } = await sync(second, { statePath }, { run: fakeRun() });

    expect(report.drifted).toBe(true);
    const state = loadState(statePath)!;
    expect(state.rules).toEqual(["192.168.0.0/16"]);
    expect(state.previous).toEqual(["10.0.0.0/8"]);
  });

  test("throws with the failing command when the runner fails", async () => {
    const wl = new Whitelist();
    wl.add("10.0.0.0/24");
    expect(
      sync(wl, {}, {
        run: async () => ({ ok: false, stdout: "", stderr: " Permission denied (iptables)" }),
      }),
    ).rejects.toThrow(/Permission denied/);
  });

  test("custom chain and interface persist in state", async () => {
    const dir = tmp();
    const statePath = join(dir, "state.json");
    const wl = new Whitelist();
    wl.add("10.0.0.0/24");
    await sync(wl, { statePath, chain: "MYCHAIN", iface: "eth0", defaultPolicy: "return" }, { run: fakeRun() });
    const state = loadState(statePath)!;
    expect(state.chain).toBe("MYCHAIN");
    expect(state.iface).toBe("eth0");
    expect(state.defaultPolicy).toBe("return");
  });
});

describe("rollback", () => {
  test("restores the previous ruleset", async () => {
    const dir = tmp();
    const statePath = join(dir, "state.json");

    const first = new Whitelist();
    first.add("10.0.0.0/8");
    await sync(first, { statePath }, { run: fakeRun() });

    const second = new Whitelist();
    second.add("192.168.0.0/16");
    await sync(second, { statePath }, { run: fakeRun() });

    const restored = await rollback({ statePath }, { run: fakeRun() });
    expect(restored).toEqual(["10.0.0.0/8"]);
    expect(loadState(statePath)!.rules).toEqual(["10.0.0.0/8"]);
  });

  test("returns null when there is no prior state", async () => {
    const dir = tmp();
    expect(await rollback({ statePath: join(dir, "absent.json") }, { run: fakeRun() })).toBeNull();
  });

  test("returns null when the last sync was the first", async () => {
    const dir = tmp();
    const statePath = join(dir, "state.json");
    const wl = new Whitelist();
    wl.add("10.0.0.0/24");
    await sync(wl, { statePath }, { run: fakeRun() });
    expect(await rollback({ statePath }, { run: fakeRun() })).toBeNull();
  });

  test("requires a state path", async () => {
    expect(rollback({}, { run: fakeRun() })).rejects.toThrow(/--state/);
  });
});

describe("state file validation", () => {
  test("rejects corrupt JSON", () => {
    const dir = tmp();
    const file = join(dir, "state.json");
    writeFileSync(file, "{broken");
    expect(() => loadState(file)).toThrow(/not valid JSON/);
  });

  test("rejects the wrong format", () => {
    const dir = tmp();
    const file = join(dir, "state.json");
    writeFileSync(file, JSON.stringify({ format: "other", version: 1 }));
    expect(() => loadState(file)).toThrow(/unrecognized format/);
  });

  test("rejects missing rules", () => {
    const dir = tmp();
    const file = join(dir, "state.json");
    writeFileSync(file, JSON.stringify({ format: STATE_FORMAT, version: 1, appliedAt: "t" }));
    expect(() => loadState(file)).toThrow(/missing appliedAt\/rules/);
  });

  test("round-trips through saveState/loadState", () => {
    const dir = tmp();
    const file = join(dir, "nested", "state.json");
    saveState(file, {
      format: STATE_FORMAT,
      version: 1,
      appliedAt: "2026-10-20T00:00:00.000Z",
      chain: "DOCKER-USER",
      defaultPolicy: "drop",
      rules: ["10.0.0.0/8"],
      previous: ["192.168.0.0/16"],
    });
    const state = loadCorruptProbe(file)!;
    expect(state.rules).toEqual(["10.0.0.0/8"]);
    expect(state.previous).toEqual(["192.168.0.0/16"]);
  });
});
