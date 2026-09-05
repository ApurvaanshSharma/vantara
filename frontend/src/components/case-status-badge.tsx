import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { CaseStatus } from "@/lib/types";

const STATUS_STYLES: Record<CaseStatus, string> = {
  open: "bg-blue-500 text-white border-transparent",
  investigating: "bg-yellow-500 text-black border-transparent",
  closed: "bg-slate-500 text-white border-transparent",
};

export function CaseStatusBadge({ status }: { status: CaseStatus }) {
  return <Badge className={cn(STATUS_STYLES[status])}>{status}</Badge>;
}
