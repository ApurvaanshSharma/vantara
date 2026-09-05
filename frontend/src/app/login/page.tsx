"use client";

import { ShieldCheck } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { register as apiRegister, ApiError } from "@/lib/api";
import { useLogin } from "@/hooks/use-auth";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mode, setMode] = useState<"login" | "register">("login");
  const [registerMessage, setRegisterMessage] = useState<string | null>(null);
  const login = useLogin();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setRegisterMessage(null);

    if (mode === "register") {
      try {
        await apiRegister(email, password);
        setRegisterMessage("Account created — you can log in now.");
        setMode("login");
      } catch (err) {
        setRegisterMessage(err instanceof ApiError ? err.message : "Registration failed");
      }
      return;
    }

    login.mutate({ email, password });
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/30 px-4">
      <Card className="w-full max-w-sm">
        <CardHeader className="items-center text-center">
          <ShieldCheck className="mb-2 h-8 w-8 text-primary" />
          <CardTitle>Vantara</CardTitle>
          <CardDescription>
            {mode === "login" ? "Sign in to your account" : "Create an analyst account"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                minLength={8}
                required
              />
            </div>

            {login.isError && (
              <p className="text-sm text-destructive">
                {login.error instanceof ApiError ? login.error.message : "Login failed"}
              </p>
            )}
            {registerMessage && <p className="text-sm text-muted-foreground">{registerMessage}</p>}

            <Button type="submit" className="w-full" disabled={login.isPending}>
              {login.isPending ? "Signing in..." : mode === "login" ? "Sign in" : "Create account"}
            </Button>
          </form>

          <button
            type="button"
            onClick={() => setMode(mode === "login" ? "register" : "login")}
            className="mt-4 w-full text-center text-sm text-muted-foreground hover:text-foreground"
          >
            {mode === "login" ? "Need an account? Register" : "Already have an account? Sign in"}
          </button>

          <p className="mt-2 text-center text-xs text-muted-foreground">
            New accounts are analysts by default — admin accounts are promoted via{" "}
            <code className="font-mono">scripts/create_admin.py</code>, not through this form.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
