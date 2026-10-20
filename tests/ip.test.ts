import { describe, expect, test } from "bun:test";
import { cidrContains, cidrSize, isIpv4, parseCidr, parseIpv4, uint32ToIp } from "../src/ip.js";

describe("parseIpv4", () => {
  test("parses a valid address into a uint32", () => {
    expect(parseIpv4("0.0.0.0")).toBe(0);
    expect(parseIpv4("255.255.255.255")).toBe(4294967295);
    expect(parseIpv4("10.0.0.1")).toBe((10 << 24 | 1) >>> 0);
  });

  test("rejects malformed input", () => {
    for (const bad of ["", "1.2.3", "1.2.3.4.5", "a.b.c.d", "1.2.3.256", "1.2.3.-4", "1.2.3.4 ", " 1.2.3.4"]) {
      expect(() => parseIpv4(bad)).toThrow(/invalid IPv4/);
    }
  });

  test("isIpv4", () => {
    expect(isIpv4("1.2.3.4")).toBe(true);
    expect(isIpv4("1.2.3.256")).toBe(false);
    expect(isIpv4("::1")).toBe(false);
  });

  test("uint32ToIp round-trips", () => {
    for (const ip of ["0.0.0.0", "1.2.3.4", "192.168.1.200", "255.255.255.255"]) {
      expect(uint32ToIp(parseIpv4(ip))).toBe(ip);
    }
  });
});

describe("parseCidr", () => {
  test("bare IP becomes /32", () => {
    const rule = parseCidr("203.0.113.7");
    expect(rule.cidr).toBe("203.0.113.7/32");
    expect(rule.prefix).toBe(32);
    expect(rule.first).toBe(rule.last);
  });

  test("normalizes host bits", () => {
    expect(parseCidr("10.1.2.3/8").cidr).toBe("10.0.0.0/8");
    expect(parseCidr("192.168.55.77/24").cidr).toBe("192.168.55.0/24");
  });

  test("range math", () => {
    const rule = parseCidr("10.0.0.0/24");
    expect(rule.first).toBe(parseIpv4("10.0.0.0"));
    expect(rule.last).toBe(parseIpv4("10.0.0.255"));
    expect(cidrSize(rule)).toBe(256);
  });

  test("/0 covers the whole space", () => {
    const rule = parseCidr("0.0.0.0/0");
    expect(rule.mask).toBe(0);
    expect(rule.last).toBe(4294967295);
    expect(cidrSize(rule)).toBe(4294967296);
  });

  test("rejects bad prefixes", () => {
    for (const bad of ["10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/", "10.0.0.0/abc", "10.0.0.0/8/9"]) {
      expect(() => parseCidr(bad)).toThrow(/invalid CIDR prefix/);
    }
  });

  test("normalizeCidr returns the canonical string", () => {
    expect(parseCidr("10.1.2.3/8").cidr).toBe("10.0.0.0/8");
  });
});

describe("cidrContains", () => {
  const block = parseCidr("203.0.113.0/24");
  test("inside", () => {
    expect(cidrContains(block, "203.0.113.0")).toBe(true);
    expect(cidrContains(block, "203.0.113.255")).toBe(true);
    expect(cidrContains(block, "203.0.113.42")).toBe(true);
  });
  test("outside", () => {
    expect(cidrContains(block, "203.0.112.255")).toBe(false);
    expect(cidrContains(block, "203.0.114.0")).toBe(false);
    expect(cidrContains(block, "10.0.0.1")).toBe(false);
  });
  test("/0 matches everything", () => {
    const any = parseCidr("0.0.0.0/0");
    expect(cidrContains(any, "1.2.3.4")).toBe(true);
    expect(cidrContains(any, "255.255.255.255")).toBe(true);
  });
  test("single host rule", () => {
    const host = parseCidr("203.0.113.7/32");
    expect(cidrContains(host, "203.0.113.7")).toBe(true);
    expect(cidrContains(host, "203.0.113.8")).toBe(false);
  });
});
