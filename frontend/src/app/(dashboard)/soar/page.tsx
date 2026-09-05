"use client";

import { useMemo, useState } from "react";

import { PlaybookPipeline } from "@/components/playbook-pipeline";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useBlockedIPs, usePlaybookRuns, useRunSoar } from "@/hooks/use-soar";

export default function SoarPage() {
  const { data: runs = [] } = usePlaybookRuns();
  const { data: blockedIPs = [] } = useBlockedIPs();
  const runSoar = useRunSoar();
  const [selectedAlertId, setSelectedAlertId] = useState<string>("");

  const distinctAlertIds = useMemo(() => {
    const seen = new Set<string>();
    for (const run of runs) seen.add(run.alert_id);
    return Array.from(seen);
  }, [runs]);

  const runsForSelected = useMemo(
    () => runs.filter((r) => r.alert_id === selectedAlertId),
    [runs, selectedAlertId],
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">SOAR Playbooks</h1>
          <p className="text-sm text-muted-foreground">
            Fixed 3-step pipeline, run against new alerts. Simulated actions — see backend
            notes on why &quot;simulated&quot; is the accurate word for the IP block step.
          </p>
        </div>
        <Button onClick={() => runSoar.mutate()} disabled={runSoar.isPending}>
          {runSoar.isPending ? "Running..." : "Run SOAR Sweep"}
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Pipeline</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {distinctAlertIds.length > 0 && (
            <Select value={selectedAlertId} onValueChange={setSelectedAlertId}>
              <SelectTrigger className="w-80">
                <SelectValue placeholder="Select an alert to view its playbook run..." />
              </SelectTrigger>
              <SelectContent>
                {distinctAlertIds.map((id) => (
                  <SelectItem key={id} value={id}>
                    {id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          <PlaybookPipeline runsForSelectedAlert={selectedAlertId ? runsForSelected : []} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Blocked IPs (simulated)</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {blockedIPs.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">None yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP Address</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Blocked At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {blockedIPs.map((b) => (
                  <TableRow key={b.id}>
                    <TableCell className="font-mono text-sm">{b.ip_address}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{b.reason}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(b.blocked_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
