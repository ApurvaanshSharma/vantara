"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { getAlerts, runDetection, scoreMl } from "@/lib/api";
import type { AlertStatus } from "@/lib/types";

// Polling interval for the "live" feel — see Phase 7 scope notes on why
// this replaces a real WebSocket push for now. 5s is frequent enough to
// feel responsive in a demo without hammering the API.
const POLL_INTERVAL_MS = 5_000;

export function useAlerts(status?: AlertStatus) {
  return useQuery({
    queryKey: ["alerts", status ?? "all"],
    queryFn: () => getAlerts(status),
    refetchInterval: POLL_INTERVAL_MS,
  });
}

export function useRunDetection() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (lookbackMinutes?: number) => runDetection(lookbackMinutes),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alerts"] }),
  });
}

export function useRunMlScore() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (lookbackMinutes?: number) => scoreMl(lookbackMinutes),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alerts"] }),
  });
}
