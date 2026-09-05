// Mirrors backend/app/detection/mitre.py's curated lookup exactly — same
// deliberate scope (only techniques this project's rules actually
// reference, not the full ATT&CK bundle). Keep these two files in sync by
// hand for now; see lib/types.ts for the same trade-off note.

export const MITRE_TECHNIQUES: Record<string, string> = {
  T1110: "Brute Force",
  "T1110.001": "Brute Force: Password Guessing",
  T1059: "Command and Scripting Interpreter",
  T1071: "Application Layer Protocol",
};

export function techniqueName(techniqueId: string): string {
  return MITRE_TECHNIQUES[techniqueId] ?? techniqueId;
}
