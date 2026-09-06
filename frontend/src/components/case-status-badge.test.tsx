import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { CaseStatus } from "@/lib/types";

import { CaseStatusBadge } from "./case-status-badge";

describe("CaseStatusBadge", () => {
  it.each<[CaseStatus, string]>([
    ["open", "bg-blue-500"],
    ["investigating", "bg-yellow-500"],
    ["closed", "bg-slate-500"],
  ])("renders the %s status with its color class", (status, expectedClass) => {
    render(<CaseStatusBadge status={status} />);

    const badge = screen.getByText(status);
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveClass(expectedClass);
  });
});
