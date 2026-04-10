/**
 * Tests for IP validation + ignored-range matching.
 */

import { describe, expect, it } from "vitest";
import { isInIgnoredRange, isValidPublicIP, isValidPublicIPv4, isValidPublicIPv6, ipToUint32 } from "./ip";

describe("isValidPublicIPv4", () => {
  it("accepts real public IPs", () => {
    expect(isValidPublicIPv4("8.8.8.8")).toBe(true);
    expect(isValidPublicIPv4("203.0.113.45")).toBe(true);
    expect(isValidPublicIPv4("1.1.1.1")).toBe(true);
  });

  it("rejects loopback, private, link-local, multicast", () => {
    expect(isValidPublicIPv4("127.0.0.1")).toBe(false);
    expect(isValidPublicIPv4("10.0.0.1")).toBe(false);
    expect(isValidPublicIPv4("172.16.0.1")).toBe(false);
    expect(isValidPublicIPv4("172.31.255.255")).toBe(false);
    expect(isValidPublicIPv4("192.168.1.1")).toBe(false);
    expect(isValidPublicIPv4("169.254.1.1")).toBe(false);
    expect(isValidPublicIPv4("224.0.0.1")).toBe(false);
    expect(isValidPublicIPv4("0.0.0.0")).toBe(false);
  });

  it("accepts addresses at the boundaries of 172.16-31", () => {
    expect(isValidPublicIPv4("172.15.0.1")).toBe(true);
    expect(isValidPublicIPv4("172.32.0.1")).toBe(true);
  });

  it("rejects malformed input", () => {
    expect(isValidPublicIPv4("not an ip")).toBe(false);
    expect(isValidPublicIPv4("1.2.3")).toBe(false);
    expect(isValidPublicIPv4("1.2.3.4.5")).toBe(false);
    expect(isValidPublicIPv4("256.0.0.1")).toBe(false);
    expect(isValidPublicIPv4("01.2.3.4")).toBe(false); // leading zero
    expect(isValidPublicIPv4(undefined)).toBe(false);
    expect(isValidPublicIPv4(null)).toBe(false);
    expect(isValidPublicIPv4(1234)).toBe(false);
  });
});

describe("isValidPublicIPv6", () => {
  it("accepts global unicast addresses", () => {
    expect(isValidPublicIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")).toBe(true);
    expect(isValidPublicIPv6("2001:2020:359:8901:64fb:9f41:4968:7816")).toBe(true);
    expect(isValidPublicIPv6("2607:f8b0:4004:800::200e")).toBe(true);
    expect(isValidPublicIPv6("2a00:1450:4001:801::200e")).toBe(true);
  });

  it("rejects loopback ::1", () => {
    expect(isValidPublicIPv6("::1")).toBe(false);
  });

  it("rejects unspecified ::", () => {
    expect(isValidPublicIPv6("::")).toBe(false);
  });

  it("rejects link-local fe80::/10", () => {
    expect(isValidPublicIPv6("fe80::1")).toBe(false);
    expect(isValidPublicIPv6("fe80::a1:b2c3:d4e5:f678")).toBe(false);
  });

  it("rejects unique local fc00::/7", () => {
    expect(isValidPublicIPv6("fc00::1")).toBe(false);
    expect(isValidPublicIPv6("fd12:3456:789a::1")).toBe(false);
  });

  it("rejects IPv4-mapped ::ffff:0:0/96", () => {
    expect(isValidPublicIPv6("::ffff:c0a8:101")).toBe(false); // ::ffff:192.168.1.1 in hex
    expect(isValidPublicIPv6("::ffff:0:0")).toBe(false);
  });

  it("rejects malformed input", () => {
    expect(isValidPublicIPv6("not an ip")).toBe(false);
    expect(isValidPublicIPv6("8.8.8.8")).toBe(false);
    expect(isValidPublicIPv6(undefined)).toBe(false);
    expect(isValidPublicIPv6(null)).toBe(false);
    expect(isValidPublicIPv6(1234)).toBe(false);
    expect(isValidPublicIPv6(":::1")).toBe(false);
    expect(isValidPublicIPv6("2001::1::2")).toBe(false); // double ::
  });
});

describe("isValidPublicIP", () => {
  it("accepts valid IPv4", () => {
    expect(isValidPublicIP("8.8.8.8")).toBe(true);
  });

  it("accepts valid IPv6", () => {
    expect(isValidPublicIP("2001:2020:359:8901:64fb:9f41:4968:7816")).toBe(true);
  });

  it("rejects private IPv4", () => {
    expect(isValidPublicIP("192.168.1.1")).toBe(false);
  });

  it("rejects link-local IPv6", () => {
    expect(isValidPublicIP("fe80::1")).toBe(false);
  });

  it("rejects non-IP strings", () => {
    expect(isValidPublicIP("hello")).toBe(false);
  });
});

describe("isInIgnoredRange with IPv6", () => {
  const cfg = {
    knockIgnoreRanges: [
      { ip32: ipToUint32("100.64.0.0"), mask: (~0 << 22) >>> 0 },
    ],
  };

  it("returns false for IPv6 addresses (ranges are IPv4-only)", () => {
    expect(isInIgnoredRange("2001:db8::1", cfg)).toBe(false);
    expect(isInIgnoredRange("fe80::1", cfg)).toBe(false);
  });
});

describe("ipToUint32", () => {
  it("encodes correctly", () => {
    expect(ipToUint32("0.0.0.0")).toBe(0);
    expect(ipToUint32("255.255.255.255")).toBe(0xffffffff);
    expect(ipToUint32("1.2.3.4")).toBe(0x01020304);
  });
});

describe("isInIgnoredRange", () => {
  const cfg = {
    knockIgnoreRanges: [
      // 100.64.0.0/10 (CGNAT)
      { ip32: ipToUint32("100.64.0.0"), mask: (~0 << 22) >>> 0 },
      // 192.168.0.0/16
      { ip32: ipToUint32("192.168.0.0"), mask: 0xffff0000 },
    ],
  };

  it("matches IPs inside the CGNAT range", () => {
    expect(isInIgnoredRange("100.64.0.1", cfg)).toBe(true);
    expect(isInIgnoredRange("100.127.255.254", cfg)).toBe(true);
  });

  it("matches IPs inside the /16 range", () => {
    expect(isInIgnoredRange("192.168.1.1", cfg)).toBe(true);
  });

  it("does not match public IPs", () => {
    expect(isInIgnoredRange("8.8.8.8", cfg)).toBe(false);
    expect(isInIgnoredRange("203.0.113.1", cfg)).toBe(false);
  });

  it("returns false for malformed input", () => {
    expect(isInIgnoredRange("not an ip", cfg)).toBe(false);
    expect(isInIgnoredRange("1.2.3", cfg)).toBe(false);
  });
});
