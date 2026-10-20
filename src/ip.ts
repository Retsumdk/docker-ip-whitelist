import type { IpRule } from "./types.js";

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function parseIpv4(input: string): number {
  const m = IPV4_RE.exec(input);
  if (!m) throw new Error(`invalid IPv4 address: ${JSON.stringify(input)}`);
  let value = 0;
  for (let i = 1; i <= 4; i++) {
    const octet = Number(m[i]);
    if (octet > 255) throw new Error(`invalid IPv4 address: ${JSON.stringify(input)} (octet ${octet} out of range)`);
    value = ((value << 8) | octet) >>> 0;
  }
  return value;
}

export function isIpv4(input: string): boolean {
  try {
    parseIpv4(input);
    return true;
  } catch {
    return false;
  }
}

export function uint32ToIp(value: number): string {
  const v = value >>> 0;
  return `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`;
}

export function parseCidr(input: string): IpRule {
  const slash = input.indexOf("/");
  const addrPart = slash === -1 ? input : input.slice(0, slash);
  const prefixPart = slash === -1 ? "32" : input.slice(slash + 1);
  if (!/^\d{1,2}$/.test(prefixPart)) throw new Error(`invalid CIDR prefix: ${JSON.stringify(input)}`);
  const prefix = Number(prefixPart);
  if (prefix > 32) throw new Error(`invalid CIDR prefix: ${JSON.stringify(input)} (prefix > 32)`);
  const network = parseIpv4(addrPart);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const base = (network & mask) >>> 0;
  return {
    cidr: `${uint32ToIp(base)}/${prefix}`,
    network: base,
    prefix,
    mask,
    first: base,
    last: (base | (~mask >>> 0)) >>> 0,
  };
}

export function normalizeCidr(input: string): string {
  return parseCidr(input).cidr;
}

export function cidrContains(rule: IpRule, ip: string): boolean {
  const value = parseIpv4(ip);
  return ((value & rule.mask) >>> 0) === rule.network;
}

export function cidrSize(rule: IpRule): number {
  return rule.last - rule.first + 1;
}
