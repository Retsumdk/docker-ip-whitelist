/**
 * docker-ip-whitelist — public library API. Built by Retsumdk.
 */
export type {
  IpRule,
  DefaultPolicy,
  SyncOptions,
  Plan,
  SyncReport,
  StateFile,
} from "./types.js";
export {
  parseIpv4,
  isIpv4,
  uint32ToIp,
  parseCidr,
  normalizeCidr,
  cidrContains,
  cidrSize,
} from "./ip.js";
export {
  Whitelist,
  parseRulesFile,
  type CheckResult,
  type AllowedIp,
  type DeniedIp,
  type ImportReport,
} from "./whitelist.js";
export { RULES_HEADER, loadRules, saveRules, type LoadedRules } from "./rules-file.js";
export { DEFAULT_CHAIN, buildPlan, renderPlan, applyPlan, successful } from "./iptables.js";
export { STATE_FORMAT, saveState, loadState } from "./state.js";
export { shellRunner, sync, rollback, type EngineDeps } from "./engine.js";
export {
  runCli,
  main,
  USAGE,
  EXIT_OK,
  EXIT_ERROR,
  EXIT_DENIED,
  type CliIo,
} from "./cli.js";
