import { describe, expect, test } from "bun:test";
import { DEFAULT_CHAIN, applyPlan, buildPlan, renderPlan, successful } from "../src/iptables.js";
import type { RunResult } from "../src/types.js";

const ok: RunResult = { ok: true, stdout: "", stderr: "" };

describe("buildPlan", () => {
  test("command sequence for two rules with drop policy", () => {
    const plan = buildPlan(["10.0.0.0/24", "203.0.113.7/32"]);
    expect(plan.chain).toBe(DEFAULT_CHAIN);
    expect(plan.defaultPolicy).toBe("drop");
    expect(plan.commands).toEqual([
      `iptables -N DOCKER-USER 2>/dev/null || true`,
      `iptables -C FORWARD -j DOCKER-USER 2>/dev/null || iptables -I FORWARD 1 -j DOCKER-USER`,
      `iptables -F DOCKER-USER`,
      `iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`,
      `iptables -A DOCKER-USER -s 10.0.0.0/24 -j ACCEPT`,
      `iptables -A DOCKER-USER -s 203.0.113.7/32 -j ACCEPT`,
      `iptables -A DOCKER-USER -j DROP`,
    ]);
  });

  test("return policy ends with RETURN", () => {
    const plan = buildPlan(["10.0.0.0/8"], { defaultPolicy: "return" });
    expect(plan.commands[plan.commands.length - 1]).toBe("iptables -A DOCKER-USER -j RETURN");
  });

  test("interface flag only on data-path commands", () => {
    const plan = buildPlan(["10.0.0.0/24"], { iface: "eth0" });
    expect(plan.iface).toBe("eth0");
    expect(plan.commands[0]).not.toContain("-i");
    expect(plan.commands[2]).not.toContain("-i");
    for (const cmd of plan.commands.slice(3)) expect(cmd).toContain('-i "eth0"');
  });

  test("custom chain name", () => {
    const plan = buildPlan([], { chain: "MYCHAIN" });
    expect(plan.chain).toBe("MYCHAIN");
    expect(plan.commands[0]).toContain("iptables -N MYCHAIN");
  });

  test("empty whitelist still pins the default policy", () => {
    const plan = buildPlan([]);
    expect(plan.rules).toEqual([]);
    expect(plan.commands[plan.commands.length - 1]).toContain("-j DROP");
  });

  test("plan is deterministic (idempotent sync)", () => {
    const a = buildPlan(["10.0.0.0/24"]);
    const b = buildPlan(["10.0.0.0/24"]);
    expect(a.commands).toEqual(b.commands);
  });
});

describe("renderPlan", () => {
  test("includes chain, policy, rules and commands", () => {
    const text = renderPlan(buildPlan(["10.0.0.0/24"], { iface: "eth0" }));
    expect(text).toContain("chain: DOCKER-USER (interface eth0)");
    expect(text).toContain("default policy for unmatched traffic: DROP");
    expect(text).toContain("10.0.0.0/24");
    expect(text).toContain("$ iptables -A DOCKER-USER -i \"eth0\" -s 10.0.0.0/24 -j ACCEPT");
  });

  test("empty ruleset noted explicitly", () => {
    expect(renderPlan(buildPlan([]))).toContain("(none");
  });
});

describe("applyPlan", () => {
  test("runs every command when all succeed", async () => {
    const plan = buildPlan(["10.0.0.0/24"]);
    const ran: string[] = [];
    const results = await applyPlan(plan, async (cmd) => {
      ran.push(cmd);
      return ok;
    });
    expect(ran).toHaveLength(plan.commands.length);
    expect(successful(results)).toBe(true);
  });

  test("stops at the first failure", async () => {
    const plan = buildPlan(["10.0.0.0/24"]);
    const ran: string[] = [];
    const results = await applyPlan(plan, async (cmd) => {
      ran.push(cmd);
      return cmd.includes("iptables -F") ? { ok: false, stdout: "", stderr: "permission denied" } : ok;
    });
    expect(ran).toHaveLength(3);
    expect(results).toHaveLength(3);
    expect(successful(results)).toBe(false);
  });

  test("successful() is false for no results", () => {
    expect(successful([])).toBe(false);
  });
});
