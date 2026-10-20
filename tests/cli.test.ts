import { describe, expect, test } from "bun:test";
import { EXIT_DENIED, EXIT_ERROR, EXIT_OK, USAGE, runCli } from "../src/cli.js";
import type { EngineDeps } from "../src/engine.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function harness() {
  const dir = mkdtempSync(join(tmpdir(), "diw-cli-"));
  const out: string[] = [];
  const err: string[] = [];
  const io = {
    out: (line: string) => out.push(line),
    err: (line: string) => err.push(line),
  };
  const ran: string[] = [];
  const fakeRun: EngineDeps = {
    run: async (cmd) => {
      ran.push(cmd);
      return { ok: true, stdout: cmd, stderr: "" };
    },
  };
  const run = (args: string[], deps: EngineDeps = fakeRun) =>
    runCli(["--file", join(dir, "rules.txt"), "--state", join(dir, "state.json"), ...args], io, deps);
  return { dir, out, err, ran, run };
}

describe("runCli — whitelist management", () => {
  test("add canonicalizes and reports entries", async () => {
    const h = harness();
    const code = await h.run(["add", "10.0.0.1", "192.168.5.0/24"]);
    expect(code).toBe(EXIT_OK);
    expect(h.out).toEqual(["added 10.0.0.1/32", "added 192.168.5.0/24"]);
  });

  test("add --json emits machine-readable output", async () => {
    const h = harness();
    await h.run(["add", "--json", "10.0.0.1"]);
    expect(JSON.parse(h.out[0])).toEqual({ added: ["10.0.0.1/32"] });
  });

  test("list shows sizes and warns about invalid lines", async () => {
    const h = harness();
    await h.run(["add", "10.0.0.0/24", "203.0.113.7"]);
    h.out.length = 0;
    const code = await h.run(["list"]);
    expect(code).toBe(EXIT_OK);
    expect(h.out[0]).toContain("10.0.0.0/24  (256 addresses)");
    expect(h.out[1]).toContain("203.0.113.7/32  (1 address)");
    expect(JSON.parse(await (async () => { h.out.length = 0; await h.run(["list", "--json"]); return h.out[0]; })()).rules).toEqual([
      "10.0.0.0/24",
      "203.0.113.7/32",
    ]);
  });

  test("remove drops entries and ignores unknown ones", async () => {
    const h = harness();
    await h.run(["add", "10.0.0.0/24"]);
    h.out.length = 0;
    const code = await h.run(["remove", "10.0.0.0/24", "172.16.0.0/12"]);
    expect(code).toBe(EXIT_OK);
    expect(h.out).toEqual(["removed 10.0.0.0/24"]);
  });

  test("add with no targets errors", async () => {
    const h = harness();
    const code = await h.run(["add"]).catch(() => EXIT_ERROR);
    expect(code).toBe(EXIT_ERROR);
    expect(h.err[0]).toContain("at least one IP or CIDR");
  });
});

describe("runCli — check", () => {
  test("ALLOW exits 0, DENY exits 2, mixed reports both", async () => {
    const h = harness();
    await h.run(["add", "10.0.0.0/24"]);
    h.out.length = 0;

    expect(await h.run(["check", "10.0.0.42"])).toBe(EXIT_OK);
    expect(h.out[0]).toBe("ALLOW 10.0.0.42 (matched 10.0.0.0/24)");

    h.out.length = 0;
    expect(await h.run(["check", "203.0.113.9"])).toBe(EXIT_DENIED);
    expect(h.out[0]).toBe("DENY  203.0.113.9");

    h.out.length = 0;
    expect(await h.run(["check", "10.0.0.1", "203.0.113.9"])).toBe(EXIT_DENIED);
    expect(h.out[0]).toContain("ALLOW");
    expect(h.out[1]).toContain("DENY");
  });

  test("check --json", async () => {
    const h = harness();
    await h.run(["add", "10.0.0.0/24"]);
    h.out.length = 0;
    await h.run(["check", "--json", "10.0.0.42", "8.8.8.8"]);
    const parsed = JSON.parse(h.out[0]);
    expect(parsed.results).toEqual([
      { ip: "10.0.0.42", allowed: true, matched: "10.0.0.0/24" },
      { ip: "8.8.8.8", allowed: false },
    ]);
  });

  test("check on an empty whitelist denies", async () => {
    const h = harness();
    expect(await h.run(["check", "1.2.3.4"])).toBe(EXIT_DENIED);
  });
});

describe("runCli — import", () => {
  test("merges entries, reports comments and invalid lines", async () => {
    const h = harness();
    await h.run(["add", "10.0.0.0/24"]);
    h.out.length = 0;
    const source = join(h.dir, "extra.txt");
    await (async () => {
      const { writeFileSync } = await import("node:fs");
      writeFileSync(source, "# added by ansible\n203.0.113.0/24\nbogus-line\n", "utf-8");
    })();
    const code = await h.run(["import", source]);
    expect(code).toBe(EXIT_OK);
    expect(h.out[0]).toBe("imported 1 new entry (1 comment line skipped)");
    expect(h.err[0]).toContain("line 3");
    h.out.length = 0;
    await h.run(["list", "--json"]);
    expect(JSON.parse(h.out[0]).rules).toEqual(["10.0.0.0/24", "203.0.113.0/24"]);
  });

  test("import requires exactly one file", async () => {
    const h = harness();
    const code = await h.run(["import"]).catch(() => EXIT_ERROR);
    expect(code).toBe(EXIT_ERROR);
    expect(h.err[0]).toContain("exactly one file");
  });
});

describe("runCli — plan / sync / rollback", () => {
  test("plan prints the command plan and writes no state", async () => {
    const h = harness();
    await h.run(["add", "10.0.0.0/24"]);
    h.out.length = 0;
    const code = await h.run(["plan", "--iface", "eth0"]);
    expect(code).toBe(EXIT_OK);
    expect(h.out.join("\n")).toContain("chain: DOCKER-USER (interface eth0)");
    expect(h.out.join("\n")).toContain("$ iptables -A DOCKER-USER -i \"eth0\" -s 10.0.0.0/24 -j ACCEPT");
  });

  test("sync --dry-run reports and does not execute", async () => {
    const h = harness();
    await h.run(["add", "10.0.0.0/24"]);
    h.out.length = 0;
    const code = await h.run(["sync", "--dry-run"]);
    expect(code).toBe(EXIT_OK);
    expect(h.out.join("\n")).toContain("dry-run: no commands were executed");
  });

  test("sync applies through the injected runner and records every command", async () => {
    const h = harness();
    await h.run(["add", "10.0.0.0/24"]);
    h.out.length = 0;
    const code = await h.run(["sync"]);
    expect(code).toBe(EXIT_OK);
    expect(h.out.join("\n")).toContain("applied 6 commands to chain DOCKER-USER");
    expect(h.ran[0]).toContain("iptables -N DOCKER-USER");
    expect(h.ran[h.ran.length - 1]).toContain("-j DROP");
  });

  test("rollback without prior state exits 2 with a note", async () => {
    const h = harness();
    expect(await h.run(["rollback"])).toBe(EXIT_DENIED);
    expect(h.out[0]).toContain("no previous ruleset");
  });

  test("rollback restores the previous ruleset", async () => {
    const h = harness();
    await h.run(["add", "10.0.0.0/8"]);
    await h.run(["sync"]);
    await h.run(["remove", "10.0.0.0/8"]);
    await h.run(["add", "192.168.0.0/16"]);
    h.out.length = 0;
    const code = await h.run(["sync"]);
    expect(code).toBe(EXIT_OK);
    h.out.length = 0;
    expect(await h.run(["rollback"])).toBe(EXIT_OK);
    expect(h.out[0]).toBe("restored previous ruleset:");
    expect(h.out[1]).toContain("10.0.0.0/8");
  });
});

describe("runCli — demo and usage", () => {
  test("demo renders verdicts and the plan", async () => {
    const h = harness();
    const code = await h.run(["demo"]);
    expect(code).toBe(EXIT_OK);
    const text = h.out.join("\n");
    expect(text).toContain("ALLOW 203.0.113.7");
    expect(text).toContain("DENY  203.0.113.8");
    expect(text).toContain("ALLOW 10.0.0.42");
    expect(text).toContain("DENY  192.0.2.99");
    expect(text).toContain("chain: DOCKER-USER (interface eth0)");
  });

  test("no command prints usage and exits 1", async () => {
    const h = harness();
    expect(await h.run([])).toBe(EXIT_ERROR);
    expect(h.out[0]).toBe(USAGE);
  });

  test("--help prints usage and exits 0", async () => {
    const h = harness();
    expect(await h.run(["--help"])).toBe(EXIT_OK);
    expect(h.out[0]).toBe(USAGE);
  });

  test("unknown command errors", async () => {
    const h = harness();
    const code = await h.run(["explode"]).catch(() => EXIT_ERROR);
    expect(code).toBe(EXIT_ERROR);
    expect(h.err[0]).toContain("unknown command");
  });

  test("bad --policy errors", async () => {
    const h = harness();
    const code = await h.run(["--policy", "allow-all", "plan"]).catch(() => EXIT_ERROR);
    expect(code).toBe(EXIT_ERROR);
    expect(h.err[0]).toContain("--policy");
  });
});
