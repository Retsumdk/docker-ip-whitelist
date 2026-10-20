export interface IpRule {
  /** Canonical "a.b.c.d/p" with host bits zeroed. */
  cidr: string;
  /** Network address as a uint32 (host bits zeroed). */
  network: number;
  prefix: number;
  /** Netmask as a uint32. */
  mask: number;
  /** First address in the range (== network). */
  first: number;
  /** Last address in the range. */
  last: number;
}

export type DefaultPolicy = "drop" | "return";

export interface SyncOptions {
  /** Restrict rules to inbound traffic on this interface (e.g. eth0). */
  iface?: string;
  /** iptables chain to populate. Default "DOCKER-USER". */
  chain?: string;
  /** What happens to non-whitelisted traffic. Default "drop". */
  defaultPolicy?: DefaultPolicy;
  /** Path of the applied-state file used for drift detection + rollback. */
  statePath?: string;
  /** Print the command plan without executing. */
  dryRun?: boolean;
}

export interface RunResult {
  ok: boolean;
  stdout: string;
  stderr: string;
}

export interface Plan {
  /** iptables chain the commands target (e.g. DOCKER-USER). */
  chain: string;
  commands: string[];
  iface?: string;
  defaultPolicy: DefaultPolicy;
  /** Canonical CIDRs, in apply order. */
  rules: string[];
}

export interface SyncReport {
  /** false only when a dry run; execution failures throw instead. */
  applied: boolean;
  dryRun: boolean;
  commandCount: number;
  ruleCount: number;
  /** true when the requested ruleset differs from the last applied one. */
  drifted: boolean;
  /** true when this sync produced a ruleset worth rolling back to. */
  changed: boolean;
  previousRules: string[] | null;
  /** One result per command (placeholders on dry runs). */
  outputs: Array<{ command: string; stdout: string }>;
}

export interface StateFile {
  format: "docker-ip-whitelist/state";
  version: 1;
  appliedAt: string;
  chain: string;
  defaultPolicy: DefaultPolicy;
  iface?: string;
  rules: string[];
  /** Ruleset that was applied before this one — used by `rollback`. */
  previous?: string[];
}
