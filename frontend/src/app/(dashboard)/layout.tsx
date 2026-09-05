"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { Sidebar } from "@/components/sidebar";
import { isAuthenticated } from "@/lib/auth";

// Client-side guard, not Next.js middleware: the access token lives in
// localStorage (see lib/auth.ts's trade-off note), which middleware
// running at the edge/server has no access to — only cookies and headers.
// An httpOnly-cookie version of auth (the noted v2 hardening step) would
// let this move to real middleware instead.
export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    if (!isAuthenticated()) {
      router.replace("/login");
    } else {
      // Gating render on a one-time client-side auth check, not mirroring
      // an external system's ongoing state.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setChecked(true);
    }
  }, [router]);

  if (!checked) return null;

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-8">{children}</main>
    </div>
  );
}
