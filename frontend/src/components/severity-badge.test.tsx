import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { AlertSeverity } from "@/lib/types";

import { SeverityBadge } from "./severity-badge";

describe("SeverityBadge", () => {
  it.each<[AlertSeverity, string]>([
    ["critical", "bg-red-600"],
    ["high", "bg-orange-500"],
    ["medium", "bg-yellow-500"],
    ["low", "bg-blue-500"],
    ["informational", "bg-slate-400"],
  ])("renders the %s severity with its color class", (severity, expectedClass) => {
    render(<SeverityBadge severity={severity} />);

    const badge = screen.getByText(severity);
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveClass(expectedClass);
  });
});
