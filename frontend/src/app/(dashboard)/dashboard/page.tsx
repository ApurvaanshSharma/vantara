"use client";

import { AlertTriangle, ShieldAlert, ShieldX, TrendingUp } from "lucide-react";

import { AlertsByTypeChart } from "@/components/alerts-by-type-chart";
import { Button } from "@/components/ui/button";
import { StatCard } from "@/components/stat-card";
import { useAlerts, useRunDetection, useRunMlScore } from "@/hooks/use-alerts";

export default function DashboardPage() {
  const { data: alerts = [], isLoading } = useAlerts();
  const runDetection = useRunDetection();
  const runMlScore = useRunMlScore();

  const newCount = alerts.filter((a) => a.status === "new").length;
  const highOrCritical = alerts.filter((a) => a.severity === "high" || a.severity === "critical").length;
  const withMitre = alerts.filter((a) => a.mitre_techniques.length > 0).length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
          <p className="text-sm text-muted-foreground">
            Refreshes automatically every few seconds.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => runDetection.mutate(undefined)} disabled={runDetection.isPending}>
            {runDetection.isPending ? "Running..." : "Run Sigma + Correlation"}
          </Button>
          <Button variant="outline" onClick={() => runMlScore.mutate(undefined)} disabled={runMlScore.isPending}>
            {runMlScore.isPending ? "Scoring..." : "Run ML Scan"}
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard title="Total Alerts" value={isLoading ? "..." : alerts.length} icon={ShieldAlert} />
        <StatCard title="New" value={isLoading ? "..." : newCount} icon={TrendingUp} />
        <StatCard title="High / Critical" value={isLoading ? "..." : highOrCritical} icon={AlertTriangle} />
        <StatCard title="Mapped to MITRE" value={isLoading ? "..." : withMitre} icon={ShieldX} />
      </div>

      <AlertsByTypeChart alerts={alerts} />
    </div>
  );
}
