#!/usr/bin/env node
/**
 * docker-ip-whitelist — manage IP whitelists for Docker-published ports
 * through the DOCKER-USER chain. Built by Retsumdk.
 */

import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { Whitelist, parseRulesFile, type ImportReport } from "./whitelist.js";
import { loadRules, saveRules, RULES_HEADER } from "./rules-file.js";
import { buildPlan, renderPlan } from "./iptables.js";
import { sync, rollback } from "./engine.js";
import type { SyncOptions } from "./types.js";
import type { EngineDeps } from "./engine.js";

export const EXIT_OK = 0;
export const EXIT_ERROR = 1;
export const EXIT_DENIED = 2;

export interface CliIo {
  out: (line: string) => void;
  err: (line: string) => void;
}

export const USAGE = `diw — docker-ip-whitelist

Manage an IP whitelist for Docker-published ports via the DOCKER-USER chain.

Usage:
  diw add <ip-or-cidr>...        Add entries to the rules file
  diw remove <ip-or-cidr>...     Remove entries from the rules file
  diw list                       Print the whitelist
  diw check <ip>...              Test IPs against the whitelist (DENY => exit 2)
  diw import <file>              Merge a plain-text rules file
  diw plan                       Print the iptables command plan (no changes)
  diw sync [--dry-run]           Apply the whitelist to the live chain
  diw rollback                   Restore the previously applied ruleset
  diw demo                       End-to-end demo on an in-memory whitelist

Options:
  --file <path>     Rules file (default: ./ip-whitelist.txt; .json also supported)
  --state <path>    Applied-state file for drift detection + rollback (default: ./diw-state.json)
  --iface <name>    Restrict rules to inbound traffic on this interface (e.g. eth0)
  --policy <p>      Default action for non-whitelisted traffic: drop (default) or return
  --chain <name>    iptables chain to manage (default: DOCKER-USER)
  --json            Machine-readable output where supported
  -h, --help        Show this help

Exit codes: 0 success · 1 error · 2 denied (check) / unresolved (rollback without prior state)
`;

function parseCli(argv: string[]): { command: string; positional: string[]; values: Record<string, unknown> } {
  const { positionals, values } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      file: { type: "string", default: "ip-whitelist.txt" },
      state: { type: "string", default: "diw-state.json" },
      iface: { type: "string" },
      policy: { type: "string", default: "drop" },
      chain: { type: "string" },
      "dry-run": { type: "boolean", default: false },
      json: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });
  const [command = "", ...rest] = positionals;
  if (command !== "" && command !== "help" && !WHITELIST_COMMANDS.has(command)) {
    throw new Error(`unknown command: ${command} (run "diw --help")`);
  }
  if (values.policy !== "drop" && values.policy !== "return") {
    throw new Error(`--policy must be "drop" or "return" (got ${JSON.stringify(values.policy)})`);
  }
  return { command, positional: rest, values };
}

const WHITELIST_COMMANDS = new Set(["add", "remove", "list", "check", "import", "plan", "sync", "rollback", "demo", "help"]);

function syncOptions(values: Record<string, unknown>): SyncOptions {
  return {
    ...(values.iface !== undefined ? { iface: values.iface as string } : {}),
    ...(values.chain !== undefined ? { chain: values.chain as string } : {}),
    defaultPolicy: values.policy as "drop" | "return",
    statePath: values.state as string,
  };
}

export async function runCli(
  argv: string[],
  io: CliIo = { out: (line) => console.log(line), err: (line) => console.error(line) },
  deps: EngineDeps = {},
): Promise<number> {
  try {
    return await dispatch(argv, io, deps);
  } catch (err: unknown) {
    io.err(`error: ${err instanceof Error ? err.message : String(err)}`);
    return EXIT_ERROR;
  }
}

async function dispatch(
  argv: string[],
  io: CliIo,
  deps: EngineDeps,
): Promise<number> {
  const { command, positional, values } = parseCli(argv);

  if (command === "" || values.help === true || command === "help") {
    io.out(USAGE);
    return values.help === true || command === "help" ? EXIT_OK : EXIT_ERROR;
  }

  switch (command) {
    case "add": {
      requireTargets(positional);
      const loaded = loadRules(values.file as string);
      const added = loaded.whitelist.add(...positional);
      saveRules(values.file as string, loaded.whitelist.list().map((r) => r.cidr));
      if (values.json === true) io.out(JSON.stringify({ added }));
      else for (const key of added) io.out(`added ${key}`);
      return EXIT_OK;
    }

    case "remove": {
      requireTargets(positional);
      const loaded = loadRules(values.file as string);
      const removed = loaded.whitelist.remove(...positional);
      saveRules(values.file as string, loaded.whitelist.list().map((r) => r.cidr));
      if (values.json === true) io.out(JSON.stringify({ removed }));
      else for (const key of removed) io.out(`removed ${key}`);
      return EXIT_OK;
    }

    case "list": {
      const loaded = loadRules(values.file as string);
      const rules = loaded.whitelist.list();
      for (const warning of loaded.invalid) io.err(`warning: line ${warning.line}: ${warning.reason}`);
      if (values.json === true) {
        io.out(JSON.stringify({ rules: rules.map((r) => r.cidr) }));
      } else if (rules.length === 0) {
        io.out("(whitelist is empty)");
      } else {
        for (const rule of rules) {
          io.out(`${rule.cidr}  (${rule.first === rule.last ? "1 address" : `${rule.last - rule.first + 1} addresses`})`);
        }
      }
      return EXIT_OK;
    }

    case "check": {
      requireTargets(positional);
      const loaded = loadRules(values.file as string);
      let denied = 0;
      const results = positional.map((ip) => {
        const verdict = loaded.whitelist.check(ip);
        if (!verdict.allowed) denied++;
        return verdict.allowed
          ? ({ ip, allowed: true, matched: verdict.matched.cidr } as const)
          : ({ ip, allowed: false } as const);
      });
      if (values.json === true) io.out(JSON.stringify({ results }));
      else {
        for (const result of results) {
          io.out(result.allowed ? `ALLOW ${result.ip} (matched ${result.matched})` : `DENY  ${result.ip}`);
        }
      }
      return denied > 0 ? EXIT_DENIED : EXIT_OK;
    }

    case "import": {
      if (positional.length !== 1) throw new Error("import takes exactly one file path");
      const { readFileSync } = await import("node:fs");
      const text = readFileSync(positional[0], "utf-8");
      const { entries, invalid, comments } = parseRulesFile(text);
      const loaded = loadRules(values.file as string);
      const added = loaded.whitelist.add(...entries);
      saveRules(values.file as string, loaded.whitelist.list().map((r) => r.cidr));
      const report: ImportReport = { invalid, comments };
      if (values.json === true) io.out(JSON.stringify({ added, ...report }));
      else {
        io.out(`imported ${added.length} new entr${added.length === 1 ? "y" : "ies"} (${comments} comment line${comments === 1 ? "" : "s"} skipped)`);
        for (const bad of report.invalid) io.err(`line ${bad.line}: ${bad.text} — ${bad.reason}`);
      }
      return EXIT_OK;
    }

    case "plan": {
      const loaded = loadRules(values.file as string);
      for (const warning of loaded.invalid) io.err(`warning: line ${warning.line}: ${warning.reason}`);
      const plan = buildPlan(loaded.whitelist.list().map((r) => r.cidr), syncOptions(values));
      io.out(renderPlan(plan));
      return EXIT_OK;
    }

    case "sync": {
      const loaded = loadRules(values.file as string);
      for (const warning of loaded.invalid) io.err(`warning: line ${warning.line}: ${warning.reason}`);
      const options = syncOptions(values);
      const { report, plan } = await sync(loaded.whitelist, { ...options, dryRun: values["dry-run"] === true }, deps);
      if (values.json === true) {
        io.out(JSON.stringify({ ...report, plan }));
      } else {
        io.out(renderPlan(plan));
        io.out("");
        if (report.dryRun) io.out("dry-run: no commands were executed");
        else io.out(`applied ${report.commandCount} command${report.commandCount === 1 ? "" : "s"} to chain ${plan.chain}`);
        if (report.drifted) io.out("note: state had drifted from the last applied ruleset — resynced");
      }
      return EXIT_OK;
    }

    case "rollback": {
      const restored = await rollback(syncOptions(values), deps);
      if (restored === null) {
        io.out("no previous ruleset to roll back to");
        return EXIT_DENIED;
      }
      if (values.json === true) io.out(JSON.stringify({ restored }));
      else {
        io.out("restored previous ruleset:");
        for (const rule of restored) io.out(`  ${rule}`);
      }
      return EXIT_OK;
    }

    case "demo": {
      const demo = new Whitelist();
      demo.add("203.0.113.7", "10.0.0.0/24", "198.51.100.0/24");
      for (const ip of ["203.0.113.7", "203.0.113.8", "10.0.0.42", "192.0.2.99"]) {
        const verdict = demo.check(ip);
        io.out(verdict.allowed ? `ALLOW ${ip} (matched ${verdict.matched.cidr})` : `DENY  ${ip}`);
      }
      io.out("");
      io.out(renderPlan(buildPlan(demo.list().map((r) => r.cidr), { iface: "eth0" })));
      return EXIT_OK;
    }

    default:
      throw new Error(`unknown command: ${command} (run "diw --help")`);
  }
}

function requireTargets(positional: string[]): void {
  if (positional.length === 0) {
    throw new Error("this command needs at least one IP or CIDR argument");
  }
}

export function main(argv: string[]): void {
  runCli(argv)
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err: unknown) => {
      console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = EXIT_ERROR;
    });
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2));
}
