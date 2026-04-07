import { describe, expect, it } from "vitest";
import {
  constantTimeEqualHex,
  constantTimeEqualString,
  generateToken,
  sha256Hex,
} from "./hash";

describe("sha256Hex", () => {
  it("hashes deterministically", () => {
    expect(sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("generateToken", () => {
  it("produces url-safe base64 of the requested length", () => {
    const a = generateToken(32);
    const b = generateToken(32);
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/u);
    // 32 bytes → 43 base64url chars (no padding)
    expect(a.length).toBeGreaterThanOrEqual(42);
  });
});

describe("constantTimeEqualHex", () => {
  it("returns true for equal hex strings", () => {
    expect(constantTimeEqualHex("deadbeef", "deadbeef")).toBe(true);
  });
  it("returns false for different hex", () => {
    expect(constantTimeEqualHex("deadbeef", "cafebabe")).toBe(false);
  });
  it("returns false for length mismatch", () => {
    expect(constantTimeEqualHex("dead", "deadbeef")).toBe(false);
  });
  it("returns false for invalid hex", () => {
    expect(constantTimeEqualHex("xyzz", "abcd")).toBe(false);
  });
});

describe("constantTimeEqualString", () => {
  it("compares byte-equal strings", () => {
    expect(constantTimeEqualString("hello", "hello")).toBe(true);
    expect(constantTimeEqualString("hello", "world")).toBe(false);
    expect(constantTimeEqualString("hello", "helloo")).toBe(false);
  });
});
