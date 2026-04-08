import { afterEach, describe, expect, it } from "vitest";
import {
  putChallenge,
  resetChallengesForTests,
  sweepChallenges,
  takeChallenge,
} from "./challenges";

afterEach(() => resetChallengesForTests());

describe("challenge store", () => {
  it("returns and consumes a fresh challenge exactly once", () => {
    putChallenge("k", "abc", 60_000);
    expect(takeChallenge("k")).toBe("abc");
    // second read is consumed
    expect(takeChallenge("k")).toBeNull();
  });

  it("returns null for an unknown key", () => {
    expect(takeChallenge("missing")).toBeNull();
  });

  it("returns null for an expired challenge and removes it", () => {
    putChallenge("k", "abc", 0); // immediately expired
    expect(takeChallenge("k")).toBeNull();
  });

  it("sweep drops expired entries", () => {
    putChallenge("a", "x", 0);
    putChallenge("b", "y", 60_000);
    const removed = sweepChallenges();
    expect(removed).toBe(1);
    expect(takeChallenge("b")).toBe("y");
  });
});
