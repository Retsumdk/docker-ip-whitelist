import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname } from "path";
import type { StateFile } from "./types.js";
import { parseCidr } from "./ip.js";

export const STATE_FORMAT = "docker-ip-whitelist/state";

export function saveState(path: string, state: StateFile): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(state, null, 2)}\n`, "utf-8");
}

export function loadState(path: string): StateFile | null {
  if (!existsSync(path)) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf-8"));
  } catch (err) {
    throw new Error(`state file ${path} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.format !== STATE_FORMAT || obj.version !== 1) {
    throw new Error(`state file ${path} has an unrecognized format (expected ${STATE_FORMAT} v1)`);
  }
  if (typeof obj.appliedAt !== "string" || !Array.isArray(obj.rules)) {
    throw new Error(`state file ${path} is missing appliedAt/rules`);
  }
  const rule = (value: unknown, what: string): string => {
    if (typeof value !== "string") throw new Error(`${what} must be a string`);
    return parseCidr(value).cidr;
  };
  const state: StateFile = {
    format: STATE_FORMAT,
    version: 1,
    appliedAt: obj.appliedAt,
    chain: typeof obj.chain === "string" ? obj.chain : "DOCKER-USER",
    defaultPolicy: obj.defaultPolicy === "return" ? "return" : "drop",
    rules: (obj.rules as unknown[]).map((r) => rule(r, "rule")),
  };
  if (typeof obj.iface === "string") state.iface = obj.iface;
  if (Array.isArray(obj.previous)) {
    state.previous = (obj.previous as unknown[]).map((r) => rule(r, "previous rule"));
  }
  return state;
}
