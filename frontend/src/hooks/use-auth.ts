"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";

import { getCurrentUser, login as apiLogin } from "@/lib/api";
import { clearTokens, isAuthenticated, setTokens } from "@/lib/auth";

export function useCurrentUser() {
  return useQuery({
    queryKey: ["currentUser"],
    queryFn: getCurrentUser,
    enabled: isAuthenticated(),
    retry: false,
  });
}

export function useLogin() {
  const router = useRouter();
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ email, password }: { email: string; password: string }) =>
      apiLogin(email, password),
    onSuccess: (token) => {
      setTokens(token.access_token, token.refresh_token);
      queryClient.invalidateQueries({ queryKey: ["currentUser"] });
      router.push("/dashboard");
    },
  });
}

export function useLogout() {
  const router = useRouter();
  const queryClient = useQueryClient();

  return () => {
    clearTokens();
    queryClient.clear();
    router.push("/login");
  };
}
