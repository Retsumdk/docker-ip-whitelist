import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname } from "path";
import { Whitelist, parseRulesFile } from "./whitelist.js";

export const RULES_HEADER = "docker-ip-whitelist rules — one IPv4 address or CIDR per line";

export interface LoadedRules {
  whitelist: Whitelist;
  fileExisted: boolean;
  invalid: Array<{ line: number; text: string; reason: string }>;
}

/** Load the rules file. Missing file => empty whitelist. Corrupt JSON => error. */
export function loadRules(path: string): LoadedRules {
  if (!existsSync(path)) return { whitelist: new Whitelist(), fileExisted: false, invalid: [] };
  const text = readFileSync(path, "utf-8");
  if (path.endsWith(".json")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      throw new Error(`rules file ${path} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
    }
    return { whitelist: fromJsonRules(parsed), fileExisted: true, invalid: [] };
  }
  const { entries, invalid } = parseRulesFile(text);
  const whitelist = new Whitelist();
  whitelist.add(...entries);
  return { whitelist, fileExisted: true, invalid };
}

function fromJsonRules(parsed: unknown): Whitelist {
  if (parsed === null || typeof parsed !== "object") throw new Error("rules JSON must be an object");
  const obj = parsed as Record<string, unknown>;
  const entries = obj.entries ?? obj.rules;
  if (!Array.isArray(entries)) throw new Error('rules JSON must contain an "entries" or "rules" array');
  const whitelist = new Whitelist();
  whitelist.add(...entries.map((e) => requireString(e, "entry")));
  return whitelist;
}

export function saveRules(path: string, rules: string[], header: string = RULES_HEADER): void {
  ensureDir(path);
  if (path.endsWith(".json")) {
    writeFileSync(path, `${JSON.stringify({ entries: rules }, null, 2)}\n`);
  } else {
    const lines = rules.join("\n");
    writeFileSync(path, `# ${header}\n${lines ? lines + "\n" : ""}`);
  }
}

function requireString(value: unknown, what: string): string {
  if (typeof value !== "string") throw new Error(`${what} must be a string`);
  return value;
}

function ensureDir(path: string): void {
  const dir = dirname(path);
  if (dir && dir !== "." && !existsSync(dir)) mkdirSync(dir, { recursive: true });
}
