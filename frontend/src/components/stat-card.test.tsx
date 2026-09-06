import { render, screen } from "@testing-library/react";
import { Activity } from "lucide-react";
import { describe, expect, it } from "vitest";

import { StatCard } from "./stat-card";

describe("StatCard", () => {
  it("renders the title and value", () => {
    render(<StatCard title="Open Alerts" value={42} icon={Activity} />);

    expect(screen.getByText("Open Alerts")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("only renders a description when one is passed", () => {
    const { rerender } = render(<StatCard title="Open Alerts" value={42} icon={Activity} />);
    expect(screen.queryByText("Since last hour")).not.toBeInTheDocument();

    rerender(
      <StatCard title="Open Alerts" value={42} icon={Activity} description="Since last hour" />,
    );
    expect(screen.getByText("Since last hour")).toBeInTheDocument();
  });
});
