import { describe, expect, it } from "vitest";

import { MITRE_TECHNIQUES, techniqueName } from "./mitre";

describe("techniqueName", () => {
  it("resolves a known technique id to its display name", () => {
    expect(techniqueName("T1110")).toBe("Brute Force");
    expect(techniqueName("T1110.001")).toBe("Brute Force: Password Guessing");
  });

  it("falls back to the raw id for a technique outside the curated list", () => {
    expect(techniqueName("T9999")).toBe("T9999");
  });

  it("stays in sync with backend/app/detection/mitre.py's curated list", () => {
    expect(Object.keys(MITRE_TECHNIQUES)).toEqual(
      expect.arrayContaining(["T1110", "T1110.001", "T1059", "T1071"]),
    );
  });
});
