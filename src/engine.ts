import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Whitelist } from "./whitelist.js";
import { buildPlan, applyPlan, successful } from "./iptables.js";
import { loadState, saveState, STATE_FORMAT } from "./state.js";
import type { Plan, RunResult, StateFile, SyncOptions, SyncReport } from "./types.js";

const execFileAsync = promisify(execFile);

export interface EngineDeps {
  /** Injectable command runner (tests pass a fake; production shells out to iptables). */
  run?: (command: string) => Promise<RunResult>;
  now?: () => string;
}

export function shellRunner(command: string): Promise<RunResult> {
  return execFileAsync("sh", ["-c", command], { timeout: 30_000 })
    .then(({ stdout }) => ({ ok: true, stdout, stderr: "" }))
    .catch((err: { stdout?: string; stderr?: string; message?: string }) => ({
      ok: false,
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? err.message ?? "command failed",
    }));
}

/**
 * Plan and (unless dryRun) apply the whitelist to the live chain, persist the
 * applied state, and keep the previous ruleset for rollback.
 */
export async function sync(
  whitelist: Whitelist,
  options: SyncOptions = {},
  deps: EngineDeps = {},
): Promise<{ report: SyncReport; plan: Plan }> {
  const statePath = options.statePath;
  const plan = buildPlan(whitelist.list().map((r) => r.cidr), options);
  const prior = statePath ? loadState(statePath) : null;

  const drifted =
    prior !== null &&
    (prior.chain !== plan.chain ||
      (prior.iface ?? undefined) !== (plan.iface ?? undefined) ||
      prior.defaultPolicy !== plan.defaultPolicy ||
      JSON.stringify(prior.rules) !== JSON.stringify(plan.rules));
  const changed = prior === null || drifted;

  let outputs: SyncReport["outputs"] = [];
  let applied = false;
  if (options.dryRun) {
    outputs = plan.commands.map((command) => ({ command, stdout: "(dry-run) not executed" }));
  } else {
    const results = await applyPlan(plan, deps.run ?? shellRunner);
    outputs = results.map((r, i) => ({ command: plan.commands[i], stdout: r.stdout }));
    applied = successful(results);
    if (!applied) {
      const failed = results[results.length - 1];
      throw new Error(
        `iptables failed on: ${plan.commands[results.length - 1]}\n${failed?.stderr || "command returned non-zero"}`,
      );
    }
    if (statePath) {
      const previousRules = prior ? prior.rules : undefined;
      const state: StateFile = {
        format: STATE_FORMAT,
        version: 1,
        appliedAt: (deps.now ?? (() => new Date().toISOString()))(),
        chain: plan.chain,
        defaultPolicy: plan.defaultPolicy,
        ...(plan.iface !== undefined ? { iface: plan.iface } : {}),
        rules: plan.rules,
        ...(previousRules !== undefined && previousRules.join(",") !== plan.rules.join(",")
          ? { previous: previousRules }
          : {}),
      };
      saveState(statePath, state);
    }
  }

  return {
    plan,
    report: {
      applied,
      dryRun: options.dryRun === true,
      commandCount: plan.commands.length,
      ruleCount: plan.rules.length,
      drifted,
      changed,
      previousRules: prior ? prior.rules : null,
      outputs,
    },
  };
}

/** Roll back to the previous applied ruleset. Returns the rules restored, or null when there is nothing to roll back to. */
export async function rollback(
  options: SyncOptions = {},
  deps: EngineDeps = {},
): Promise<string[] | null> {
  if (!options.statePath) throw new Error("rollback requires --state");
  const prior = loadState(options.statePath);
  if (!prior || !prior.previous) return null;

  const whitelist = new Whitelist();
  whitelist.add(...prior.previous);
  await sync(whitelist, { ...options, dryRun: false }, deps);
  return prior.previous;
}
