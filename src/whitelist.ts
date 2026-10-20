import type { IpRule } from "./types.js";
import { cidrContains, parseCidr } from "./ip.js";

export type AllowedIp = { allowed: true; matched: IpRule };
export type DeniedIp = { allowed: false };
export type CheckResult = AllowedIp | DeniedIp;

/** Ordered set of whitelisted CIDRs keyed by canonical "net/prefix". */
export class Whitelist {
  private rules = new Map<string, IpRule>();

  /** Adds one or more CIDRs/IPs. Returns the canonical keys actually added. */
  add(...inputs: string[]): string[] {
    const added: string[] = [];
    for (const input of inputs) {
      const rule = parseCidr(input);
      if (!this.rules.has(rule.cidr)) {
        this.rules.set(rule.cidr, rule);
        added.push(rule.cidr);
      }
    }
    return added;
  }

  /** Removes rules; unknown entries are ignored. Returns removed keys. */
  remove(...inputs: string[]): string[] {
    const removed: string[] = [];
    for (const input of inputs) {
      const rule = parseCidr(input);
      if (this.rules.delete(rule.cidr)) removed.push(rule.cidr);
    }
    return removed;
  }

  list(): IpRule[] {
    return [...this.rules.values()].sort((a, b) => a.network - b.network || a.prefix - b.prefix);
  }

  size(): number {
    return this.rules.size;
  }

  check(ip: string): CheckResult {
    for (const rule of this.list()) {
      if (cidrContains(rule, ip)) return { allowed: true, matched: rule };
    }
    return { allowed: false };
  }

  clear(): void {
    this.rules.clear();
  }
}

export interface ImportReport {
  invalid: Array<{ line: number; text: string; reason: string }>;
  comments: number;
}
/**
 * Parse a plain-text rules file: one IP/CIDR per line, `#` or `;` comments
 * (full-line or trailing after whitespace), blank lines skipped. Invalid
 * lines are reported with their line number instead of aborting.
 */
export function parseRulesFile(text: string): { entries: string[]; invalid: Array<{ line: number; text: string; reason: string }>; comments: number } {
  const entries: string[] = [];
  const invalid: ImportReport["invalid"] = [];
  let comments = 0;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim();
    if (line === "") continue;
    if (line.startsWith("#") || line.startsWith(";")) {
      comments++;
      continue;
    }
    const hashAt = line.search(/[;\s]#/);
    if (hashAt !== -1) {
      line = line.slice(0, hashAt).trim();
      comments++;
    }
    if (line === "") continue;
    try {
      entries.push(parseCidr(line).cidr);
    } catch (err) {
      invalid.push({ line: i + 1, text: lines[i].trim(), reason: err instanceof Error ? err.message : String(err) });
    }
  }
  return { entries, invalid, comments };
}
