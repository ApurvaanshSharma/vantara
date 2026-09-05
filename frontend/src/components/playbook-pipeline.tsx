"use client";

import { Background, Handle, Position, ReactFlow, type Edge, type Node } from "@xyflow/react";
import { useMemo } from "react";

import "@xyflow/react/dist/style.css";

import type { PlaybookName, PlaybookRunOut } from "@/lib/types";

const PIPELINE_ORDER: { key: PlaybookName | "trigger"; label: string }[] = [
  { key: "trigger", label: "Alert Fires" },
  { key: "auto_tag", label: "Auto-Tag" },
  { key: "simulated_ip_block", label: "Simulated IP Block" },
  { key: "auto_case_notify", label: "Case + Notify" },
];

const STATUS_COLORS: Record<string, string> = {
  success: "#22c55e",
  skipped: "#eab308",
  failed: "#ef4444",
  trigger: "#3b82f6",
  pending: "#52525b",
};

function PipelineNode({ data }: { data: { label: string; status: string; detail?: string } }) {
  const color = STATUS_COLORS[data.status] ?? STATUS_COLORS.pending;
  return (
    <div
      className="rounded-lg border-2 px-4 py-3 text-center text-sm shadow-sm"
      style={{ borderColor: color, background: "var(--card)", minWidth: 160 }}
    >
      <Handle type="target" position={Position.Left} style={{ background: color }} />
      <p className="font-medium">{data.label}</p>
      <p className="text-xs capitalize" style={{ color }}>
        {data.status}
      </p>
      {data.detail && <p className="mt-1 text-xs text-muted-foreground">{data.detail}</p>}
      <Handle type="source" position={Position.Right} style={{ background: color }} />
    </div>
  );
}

const nodeTypes = { pipeline: PipelineNode };

export function PlaybookPipeline({
  runsForSelectedAlert,
}: {
  runsForSelectedAlert: PlaybookRunOut[];
}) {
  const { nodes, edges } = useMemo(() => {
    const runByName = new Map(runsForSelectedAlert.map((r) => [r.playbook_name, r]));

    const nodes: Node[] = PIPELINE_ORDER.map((step, i) => {
      let status = "pending";
      let detail: string | undefined;

      if (step.key === "trigger") {
        status = runsForSelectedAlert.length > 0 ? "trigger" : "pending";
      } else {
        const run = runByName.get(step.key);
        if (run) {
          status = run.status;
          if (step.key === "simulated_ip_block" && run.result.ip_address) {
            detail = String(run.result.ip_address);
          }
          if (step.key === "auto_case_notify" && run.result.case_id) {
            detail = `case ${String(run.result.case_id).slice(0, 8)}...`;
          }
        }
      }

      return {
        id: step.key,
        type: "pipeline",
        position: { x: i * 220, y: 0 },
        data: { label: step.label, status, detail },
      };
    });

    const edges: Edge[] = PIPELINE_ORDER.slice(1).map((step, i) => ({
      id: `${PIPELINE_ORDER[i].key}-${step.key}`,
      source: PIPELINE_ORDER[i].key,
      target: step.key,
      animated: runsForSelectedAlert.length > 0,
    }));

    return { nodes, edges };
  }, [runsForSelectedAlert]);

  return (
    <div style={{ height: 220 }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        proOptions={{ hideAttribution: true }}
      >
        <Background />
      </ReactFlow>
    </div>
  );
}
