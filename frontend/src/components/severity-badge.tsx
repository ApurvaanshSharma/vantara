import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { AlertSeverity } from "@/lib/types";

const SEVERITY_STYLES: Record<AlertSeverity, string> = {
  critical: "bg-red-600 text-white border-transparent",
  high: "bg-orange-500 text-white border-transparent",
  medium: "bg-yellow-500 text-black border-transparent",
  low: "bg-blue-500 text-white border-transparent",
  informational: "bg-slate-400 text-white border-transparent",
};

export function SeverityBadge({ severity }: { severity: AlertSeverity }) {
  return <Badge className={cn(SEVERITY_STYLES[severity])}>{severity}</Badge>;
}
