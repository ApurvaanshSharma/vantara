"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  addCaseComment,
  closeCase,
  createCase,
  getCase,
  getCaseComments,
  getCases,
  updateCase,
} from "@/lib/api";
import type { CaseStatus } from "@/lib/types";

export function useCases(status?: CaseStatus) {
  return useQuery({
    queryKey: ["cases", status ?? "all"],
    queryFn: () => getCases(status),
    refetchInterval: 5_000,
  });
}

export function useCase(id: string) {
  return useQuery({ queryKey: ["case", id], queryFn: () => getCase(id), enabled: !!id });
}

export function useCaseComments(caseId: string) {
  return useQuery({
    queryKey: ["case-comments", caseId],
    queryFn: () => getCaseComments(caseId),
    enabled: !!caseId,
  });
}

export function useCreateCase() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: createCase,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cases"] }),
  });
}

export function useUpdateCase(id: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { status?: CaseStatus; tags?: string[] }) => updateCase(id, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["case", id] });
      queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
  });
}

export function useCloseCase(id: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => closeCase(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["case", id] });
      queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
  });
}

export function useAddComment(caseId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: string) => addCaseComment(caseId, body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["case-comments", caseId] }),
  });
}
