import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { SeverityBadge } from "@/components/severity-badge";
import { techniqueName } from "@/lib/mitre";
import type { AlertOut } from "@/lib/types";

export function AlertDetailDialog({
  alert,
  open,
  onOpenChange,
}: {
  alert: AlertOut | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  if (!alert) return null;

  const threatIntel = alert.details.threat_intel as Record<string, unknown> | undefined;
  const shapContributors = alert.details.top_shap_contributors as
    | { feature: string; shap_value: number }[]
    | undefined;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{alert.rule_title}</DialogTitle>
          <DialogDescription>{alert.summary}</DialogDescription>
        </DialogHeader>

        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={alert.severity} />
          <Badge variant="outline">{alert.detection_type}</Badge>
          <Badge variant="outline">{alert.status}</Badge>
        </div>

        {alert.mitre_techniques.length > 0 && (
          <div>
            <h4 className="mb-2 text-sm font-medium">MITRE ATT&CK Techniques</h4>
            <div className="flex flex-wrap gap-2">
              {alert.mitre_techniques.map((technique) => (
                <Badge key={technique} variant="secondary">
                  {technique} — {techniqueName(technique)}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {shapContributors && shapContributors.length > 0 && (
          <div>
            <h4 className="mb-2 text-sm font-medium">Top Contributing Features (SHAP)</h4>
            <div className="space-y-1">
              {shapContributors.map((c) => (
                <div key={c.feature} className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">{c.feature}</span>
                  <span className={c.shap_value >= 0 ? "text-red-500" : "text-green-500"}>
                    {c.shap_value >= 0 ? "+" : ""}
                    {c.shap_value.toFixed(4)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {threatIntel && (
          <div>
            <h4 className="mb-2 text-sm font-medium">Threat Intelligence</h4>
            <div className="rounded-md border p-3 text-sm space-y-1">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Combined threat score</span>
                <span>{String(threatIntel.combined_threat_score)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">AbuseIPDB score</span>
                <span>{String(threatIntel.abuseipdb_score)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">OTX pulse count</span>
                <span>{String(threatIntel.otx_pulse_count)}</span>
              </div>
            </div>
          </div>
        )}

        <Separator />

        <div>
          <h4 className="mb-2 text-sm font-medium">Raw Details</h4>
          <pre className="max-h-64 overflow-auto rounded-md bg-muted p-3 text-xs">
            {JSON.stringify(alert.details, null, 2)}
          </pre>
        </div>
      </DialogContent>
    </Dialog>
  );
}
