import { Card, CardContent } from "@/components/ui/card";
import { MITRE_TECHNIQUES, techniqueName } from "@/lib/mitre";
import { cn } from "@/lib/utils";
import type { AlertOut } from "@/lib/types";

// Simplified heatmap — a grid of tiles for the techniques this project's
// own rules can produce (see backend/app/detection/mitre.py), not the
// full ATT&CK Navigator matrix (~600 techniques across 14 tactics). Same
// deliberate scope as the backend's own curated lookup this mirrors.
function intensityClass(count: number, max: number): string {
  if (count === 0) return "bg-muted text-muted-foreground";
  const ratio = count / max;
  if (ratio > 0.75) return "bg-red-600 text-white";
  if (ratio > 0.5) return "bg-orange-500 text-white";
  if (ratio > 0.25) return "bg-yellow-500 text-black";
  return "bg-blue-400 text-white";
}

export function MitreHeatmap({ alerts }: { alerts: AlertOut[] }) {
  const counts: Record<string, number> = {};
  for (const technique of Object.keys(MITRE_TECHNIQUES)) counts[technique] = 0;
  for (const alert of alerts) {
    for (const technique of alert.mitre_techniques) {
      counts[technique] = (counts[technique] ?? 0) + 1;
    }
  }
  const max = Math.max(1, ...Object.values(counts));

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {Object.entries(counts).map(([technique, count]) => (
        <Card key={technique} className={cn("transition-colors", intensityClass(count, max))}>
          <CardContent className="p-4">
            <p className="font-mono text-xs opacity-80">{technique}</p>
            <p className="mt-1 text-sm font-medium">{techniqueName(technique)}</p>
            <p className="mt-2 text-2xl font-bold">{count}</p>
            <p className="text-xs opacity-80">alert{count === 1 ? "" : "s"}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
