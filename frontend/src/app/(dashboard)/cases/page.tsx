"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { CaseStatusBadge } from "@/components/case-status-badge";
import { NewCaseDialog } from "@/components/new-case-dialog";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useCases } from "@/hooks/use-cases";
import type { CaseStatus } from "@/lib/types";

export default function CasesPage() {
  const router = useRouter();
  const [statusFilter, setStatusFilter] = useState<CaseStatus | "all">("all");
  const { data: cases = [], isLoading } = useCases(
    statusFilter === "all" ? undefined : statusFilter,
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Cases</h1>
          <p className="text-sm text-muted-foreground">
            Manually created, or auto-opened by the auto_case_notify playbook for
            high/critical severity alerts.
          </p>
        </div>
        <NewCaseDialog />
      </div>

      <Tabs value={statusFilter} onValueChange={(v) => setStatusFilter(v as CaseStatus | "all")}>
        <TabsList>
          <TabsTrigger value="all">All</TabsTrigger>
          <TabsTrigger value="open">Open</TabsTrigger>
          <TabsTrigger value="investigating">Investigating</TabsTrigger>
          <TabsTrigger value="closed">Closed</TabsTrigger>
        </TabsList>
      </Tabs>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <p className="py-8 text-center text-sm text-muted-foreground">Loading...</p>
          ) : cases.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              No cases in this view.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Tags</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {cases.map((c) => (
                  <TableRow
                    key={c.id}
                    className="cursor-pointer"
                    onClick={() => router.push(`/cases/${c.id}`)}
                  >
                    <TableCell>
                      <CaseStatusBadge status={c.status} />
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={c.severity} />
                    </TableCell>
                    <TableCell className="font-medium">{c.title}</TableCell>
                    <TableCell className="text-muted-foreground text-xs">
                      {c.tags.join(", ") || "—"}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(c.created_at).toLocaleString()}
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
