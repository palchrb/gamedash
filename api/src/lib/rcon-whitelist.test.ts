import { describe, expect, it } from "vitest";
import { isRconCommandAllowed, listAllowedRconCommands } from "./rcon-whitelist";

describe("isRconCommandAllowed", () => {
  it("accepts common admin commands", () => {
    expect(isRconCommandAllowed("list")).toBe(true);
    expect(isRconCommandAllowed("say hello")).toBe(true);
    expect(isRconCommandAllowed("time set day")).toBe(true);
    expect(isRconCommandAllowed("whitelist list")).toBe(true);
    expect(isRconCommandAllowed("gamemode creative Notch")).toBe(true);
  });

  it("tolerates a leading slash", () => {
    expect(isRconCommandAllowed("/say hi")).toBe(true);
  });

  it("is case-insensitive on the first word", () => {
    expect(isRconCommandAllowed("LIST")).toBe(true);
    expect(isRconCommandAllowed("SaY hi")).toBe(true);
  });

  it("rejects empty and whitespace-only input", () => {
    expect(isRconCommandAllowed("")).toBe(false);
    expect(isRconCommandAllowed("   ")).toBe(false);
  });

  it("rejects unknown commands", () => {
    expect(isRconCommandAllowed("execute as @a run fn evil")).toBe(false);
    expect(isRconCommandAllowed("stop")).toBe(false); // only via admin stop route
    expect(isRconCommandAllowed("reload")).toBe(false);
    expect(isRconCommandAllowed("plugin")).toBe(false);
  });

  it("exposes a sorted allow list for UI autocomplete", () => {
    const list = listAllowedRconCommands();
    expect(Array.isArray(list)).toBe(true);
    expect(list.length).toBeGreaterThan(0);
    const sorted = [...list].sort();
    expect(list).toEqual(sorted);
  });
});
