"use client";

import { useState } from "react";

import { AlertsTable } from "@/components/alerts-table";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAlerts } from "@/hooks/use-alerts";
import type { AlertStatus } from "@/lib/types";

export default function AlertsPage() {
  const [statusFilter, setStatusFilter] = useState<AlertStatus | "all">("all");
  const { data: alerts = [], isLoading } = useAlerts(
    statusFilter === "all" ? undefined : statusFilter,
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Alerts</h1>
        <p className="text-sm text-muted-foreground">Click a row for full details.</p>
      </div>

      <Tabs value={statusFilter} onValueChange={(v) => setStatusFilter(v as AlertStatus | "all")}>
        <TabsList>
          <TabsTrigger value="all">All</TabsTrigger>
          <TabsTrigger value="new">New</TabsTrigger>
          <TabsTrigger value="acknowledged">Acknowledged</TabsTrigger>
          <TabsTrigger value="closed">Closed</TabsTrigger>
        </TabsList>
      </Tabs>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <p className="py-8 text-center text-sm text-muted-foreground">Loading...</p>
          ) : (
            <AlertsTable alerts={alerts} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
