import type { DefaultPolicy, Plan, RunResult, SyncOptions } from "./types.js";

export const DEFAULT_CHAIN = "DOCKER-USER";

/**
 * Build the idempotent iptables plan that pins the whitelist into the
 * DOCKER-USER chain — the chain Docker guarantees stays first in FORWARD and
 * never gets flushed by daemon restarts or network recreation.
 */
export function buildPlan(rules: string[], options: SyncOptions = {}): Plan {
  const chain = options.chain || DEFAULT_CHAIN;
  const defaultPolicy: DefaultPolicy = options.defaultPolicy ?? "drop";
  const iface = options.iface;
  const commands: string[] = [];
  const ifacePart = iface ? ` -i ${JSON.stringify(iface)}` : "";

  commands.push(`iptables -N ${chain} 2>/dev/null || true`);
  commands.push(`iptables -C FORWARD -j ${chain} 2>/dev/null || iptables -I FORWARD 1 -j ${chain}`);
  commands.push(`iptables -F ${chain}`);
  commands.push(`iptables -A ${chain}${ifacePart} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`);
  for (const rule of rules) {
    commands.push(`iptables -A ${chain}${ifacePart} -s ${rule} -j ACCEPT`);
  }
  commands.push(
    defaultPolicy === "drop"
      ? `iptables -A ${chain}${ifacePart} -j DROP`
      : `iptables -A ${chain}${ifacePart} -j RETURN`,
  );

  return {
    chain,
    ...(iface !== undefined ? { iface } : {}),
    defaultPolicy,
    rules,
    commands,
  };
}

export function renderPlan(plan: Plan): string {
  const lines: string[] = [];
  lines.push(`chain: ${plan.chain}${plan.iface ? ` (interface ${plan.iface})` : ""}`);
  lines.push(`default policy for unmatched traffic: ${plan.defaultPolicy.toUpperCase()}`);
  lines.push(`whitelisted sources (${plan.rules.length}):`);
  if (plan.rules.length === 0) {
    lines.push("  (none — every packet hits the default policy)");
  } else {
    for (const rule of plan.rules) lines.push(`  ${rule}`);
  }
  lines.push("commands:");
  for (const command of plan.commands) lines.push(`  $ ${command}`);
  return lines.join("\n");
}

/** Run every command in order; stop at the first failure. */
export async function applyPlan(
  plan: Plan,
  run: (command: string) => Promise<RunResult>,
): Promise<RunResult[]> {
  const results: RunResult[] = [];
  for (const command of plan.commands) {
    const result = await run(command);
    results.push(result);
    if (!result.ok) break;
  }
  return results;
}

export function successful(results: RunResult[]): boolean {
  return results.length > 0 && results.every((r) => r.ok);
}
