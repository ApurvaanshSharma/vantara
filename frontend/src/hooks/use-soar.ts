"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { getBlockedIPs, getPlaybookRuns, runSoar } from "@/lib/api";

export function usePlaybookRuns() {
  return useQuery({
    queryKey: ["playbook-runs"],
    queryFn: getPlaybookRuns,
    refetchInterval: 5_000,
  });
}

export function useBlockedIPs() {
  return useQuery({
    queryKey: ["blocked-ips"],
    queryFn: getBlockedIPs,
    refetchInterval: 5_000,
  });
}

export function useRunSoar() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: runSoar,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["playbook-runs"] });
      queryClient.invalidateQueries({ queryKey: ["blocked-ips"] });
      queryClient.invalidateQueries({ queryKey: ["cases"] });
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
  });
}
