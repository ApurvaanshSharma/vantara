"use client";

import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { AlertOut, DetectionType } from "@/lib/types";

const COLORS: Record<DetectionType, string> = {
  sigma: "#3b82f6",
  correlation: "#f59e0b",
  yara: "#ef4444",
  ml: "#8b5cf6",
};

export function AlertsByTypeChart({ alerts }: { alerts: AlertOut[] }) {
  const counts: Record<string, number> = { sigma: 0, correlation: 0, yara: 0, ml: 0 };
  for (const alert of alerts) counts[alert.detection_type] += 1;

  const data = Object.entries(counts).map(([type, count]) => ({ type, count }));

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Alerts by Detection Type</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
            <XAxis dataKey="type" fontSize={12} tickLine={false} />
            <YAxis fontSize={12} tickLine={false} allowDecimals={false} />
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--card)",
                border: "1px solid var(--border)",
                borderRadius: "0.5rem",
              }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {data.map((entry) => (
                <Cell key={entry.type} fill={COLORS[entry.type as DetectionType]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
