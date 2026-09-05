"use client";

import { MitreHeatmap } from "@/components/mitre-heatmap";
import { useAlerts } from "@/hooks/use-alerts";

export default function MitrePage() {
  const { data: alerts = [], isLoading } = useAlerts();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">MITRE ATT&CK</h1>
        <p className="text-sm text-muted-foreground">
          Techniques this platform&apos;s rules can currently detect — see{" "}
          <code className="font-mono text-xs">backend/app/detection/mitre.py</code> for the
          curated (not full-ATT&CK) scope.
        </p>
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : (
        <MitreHeatmap alerts={alerts} />
      )}
    </div>
  );
}
