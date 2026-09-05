"use client";

import { LayoutDashboard, ShieldAlert, Grid3x3, LogOut, ShieldCheck, Briefcase, Workflow } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { ThemeToggle } from "@/components/theme-toggle";
import { cn } from "@/lib/utils";
import { useCurrentUser, useLogout } from "@/hooks/use-auth";

const NAV_ITEMS = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/alerts", label: "Alerts", icon: ShieldAlert },
  { href: "/mitre", label: "MITRE ATT&CK", icon: Grid3x3 },
  { href: "/cases", label: "Cases", icon: Briefcase },
  { href: "/soar", label: "SOAR Playbooks", icon: Workflow },
];

export function Sidebar() {
  const pathname = usePathname();
  const { data: user } = useCurrentUser();
  const logout = useLogout();

  return (
    <aside className="flex h-screen w-64 flex-col border-r bg-card">
      <div className="flex items-center gap-2 px-6 py-5">
        <ShieldCheck className="h-6 w-6 text-primary" />
        <span className="text-lg font-semibold tracking-tight">Vantara</span>
      </div>
      <Separator />
      <nav className="flex-1 space-y-1 px-3 py-4">
        {NAV_ITEMS.map((item) => {
          const isActive = pathname?.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
              )}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <Separator />
      <div className="flex items-center justify-between gap-2 px-4 py-4">
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">{user?.email ?? "..."}</p>
          <p className="text-xs text-muted-foreground capitalize">{user?.role ?? ""}</p>
        </div>
        <div className="flex items-center gap-1">
          <ThemeToggle />
          <Button variant="ghost" size="icon" onClick={logout} aria-label="Log out">
            <LogOut className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </aside>
  );
}
