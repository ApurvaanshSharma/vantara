"use client";

import { useState } from "react";

import { AlertDetailDialog } from "@/components/alert-detail-dialog";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AlertOut } from "@/lib/types";

export function AlertsTable({ alerts }: { alerts: AlertOut[] }) {
  const [selected, setSelected] = useState<AlertOut | null>(null);

  if (alerts.length === 0) {
    return <p className="py-8 text-center text-sm text-muted-foreground">No alerts in this view.</p>;
  }

  return (
    <>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Severity</TableHead>
            <TableHead>Rule</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>MITRE</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Created</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {alerts.map((alert) => (
            <TableRow
              key={alert.id}
              className="cursor-pointer"
              onClick={() => setSelected(alert)}
            >
              <TableCell>
                <SeverityBadge severity={alert.severity} />
              </TableCell>
              <TableCell className="font-medium">{alert.rule_title}</TableCell>
              <TableCell>
                <Badge variant="outline">{alert.detection_type}</Badge>
              </TableCell>
              <TableCell>
                {alert.mitre_techniques.length > 0 ? alert.mitre_techniques.join(", ") : "—"}
              </TableCell>
              <TableCell className="capitalize">{alert.status}</TableCell>
              <TableCell className="text-muted-foreground">
                {new Date(alert.created_at).toLocaleString()}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <AlertDetailDialog
        alert={selected}
        open={selected !== null}
        onOpenChange={(open) => !open && setSelected(null)}
      />
    </>
  );
}
