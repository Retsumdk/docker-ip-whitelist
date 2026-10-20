import { describe, expect, test } from "bun:test";
import { Whitelist, parseRulesFile } from "../src/whitelist.js";
import { loadRules, saveRules, RULES_HEADER } from "../src/rules-file.js";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const tmp = () => mkdtempSync(join(tmpdir(), "diw-"));

describe("Whitelist", () => {
  test("add canonicalizes and dedupes", () => {
    const wl = new Whitelist();
    expect(wl.add("10.0.0.1", "10.0.0.0/24", "10.1.2.3/8")).toEqual(["10.0.0.1/32", "10.0.0.0/24", "10.0.0.0/8"]);
    expect(wl.size()).toBe(3);
    expect(wl.add("10.0.0.1")).toEqual([]);
    expect(wl.size()).toBe(3);
  });

  test("remove drops known entries and ignores unknown ones", () => {
    const wl = new Whitelist();
    wl.add("10.0.0.0/24", "192.168.0.0/16");
    expect(wl.remove("10.0.0.0/24", "172.16.0.0/12")).toEqual(["10.0.0.0/24"]);
    expect(wl.list().map((r) => r.cidr)).toEqual(["192.168.0.0/16"]);
  });

  test("list is sorted by network then prefix", () => {
    const wl = new Whitelist();
    wl.add("192.168.0.0/16", "10.0.0.0/8", "10.0.0.0/24");
    expect(wl.list().map((r) => r.cidr)).toEqual(["10.0.0.0/8", "10.0.0.0/24", "192.168.0.0/16"]);
  });

  test("check reports the matched rule", () => {
    const wl = new Whitelist();
    wl.add("10.0.0.0/16", "203.0.113.7");
    expect(wl.check("10.0.99.9")).toEqual({ allowed: true, matched: wl.list()[0] });
    expect(wl.check("203.0.113.7").allowed).toBe(true);
    expect(wl.check("203.0.113.8")).toEqual({ allowed: false });
  });

  test("rejects unparseable entries on add", () => {
    const wl = new Whitelist();
    expect(() => wl.add("not-an-ip")).toThrow(/invalid IPv4/);
  });

  test("clear empties the set", () => {
    const wl = new Whitelist();
    wl.add("10.0.0.0/8");
    wl.clear();
    expect(wl.size()).toBe(0);
    expect(wl.check("10.0.0.1").allowed).toBe(false);
  });
});

describe("parseRulesFile", () => {
  test("parses entries, skips comments and blanks, counts both", () => {
    const text = [
      "# office range",
      "10.0.0.0/24",
      "",
      "; vpn gateway",
      "203.0.113.7   # delegated exit node",
      "not-an-ip",
    ].join("\n");
    const { entries, invalid, comments } = parseRulesFile(text);
    expect(entries).toEqual(["10.0.0.0/24", "203.0.113.7/32"]);
    expect(comments).toBe(3);
    expect(invalid).toEqual([{ line: 6, text: "not-an-ip", reason: expect.stringMatching(/invalid IPv4/) }]);
  });

  test("handles CRLF and host-bit normalization", () => {
    const { entries } = parseRulesFile("192.168.55.77/24\r\n# c\r\n10.1.2.3\r\n");
    expect(entries).toEqual(["192.168.55.0/24", "10.1.2.3/32"]);
  });

  test("empty input yields nothing", () => {
    expect(parseRulesFile("").entries).toEqual([]);
  });
});

describe("rules file persistence", () => {
  test("text format round-trips with a header", () => {
    const dir = tmp();
    const file = join(dir, "ip-whitelist.txt");
    saveRules(file, ["10.0.0.0/24"], undefined as never);
    const text = readFileSync(file, "utf-8");
    expect(text).toContain(RULES_HEADER);
    const loaded = loadRules(file);
    expect(loaded.whitelist.list().map((r) => r.cidr)).toEqual(["10.0.0.0/24"]);
  });

  test("JSON format accepts entries or rules arrays and rejects garbage", () => {
    const dir = tmp();
    const entries = join(dir, "a.json");
    writeFileSync(entries, JSON.stringify({ entries: ["10.0.0.0/8"] }));
    expect(loadRules(entries).whitelist.size()).toBe(1);

    const rules = join(dir, "b.json");
    writeFileSync(rules, JSON.stringify({ rules: ["192.168.0.0/16"] }));
    expect(loadRules(rules).whitelist.size()).toBe(1);

    const corrupt = join(dir, "c.json");
    writeFileSync(corrupt, "{nope");
    expect(() => loadRules(corrupt)).toThrow(/not valid JSON/);

    const wrong = join(dir, "d.json");
    writeFileSync(wrong, JSON.stringify({ nope: 1 }));
    expect(() => loadRules(wrong)).toThrow(/entries.*or.*rules/);
  });

  test("missing file loads empty", () => {
    const loaded = loadRules(join(tmp(), "absent.txt"));
    expect(loaded.fileExisted).toBe(false);
    expect(loaded.whitelist.size()).toBe(0);
  });

  test("invalid lines surface through loadRules", () => {
    const dir = tmp();
    const file = join(dir, "rules.txt");
    writeFileSync(file, "10.0.0.0/24\nbogus\n");
    const loaded = loadRules(file);
    expect(loaded.whitelist.size()).toBe(1);
    expect(loaded.invalid).toHaveLength(1);
    expect(loaded.invalid[0].line).toBe(2);
  });

  test("saveRules JSON keeps entries canonical", () => {
    const dir = tmp();
    const file = join(dir, "rules.json");
    saveRules(file, ["10.0.0.0/8"]);
    expect(JSON.parse(readFileSync(file, "utf-8")).entries).toEqual(["10.0.0.0/8"]);
  });
});
