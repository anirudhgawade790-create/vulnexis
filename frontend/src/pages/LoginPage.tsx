import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Activity, ArrowUpRight, Loader2, ShieldCheck } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/useAuth"; // we'll create a thin wrapper

const schema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

type FormValues = z.infer<typeof schema>;

export function LoginPage() {
  const { signIn } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as any)?.from?.pathname ?? "/";
  const [error, setError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({ resolver: zodResolver(schema) });

  const onSubmit = async (data: FormValues) => {
    setError(null);
    try {
      await signIn(data.username, data.password);
      navigate(from, { replace: true });
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? "Login failed");
    }
  };

  return (
    <div className="relative flex min-h-[100dvh] items-center justify-center overflow-hidden bg-background px-4 py-10">
      <div className="pointer-events-none absolute inset-0 opacity-30 [background-image:linear-gradient(hsl(var(--border))_1px,transparent_1px),linear-gradient(90deg,hsl(var(--border))_1px,transparent_1px)] [background-size:54px_54px] [mask-image:radial-gradient(ellipse_at_center,black,transparent_75%)]" />
      <div className="relative grid w-full max-w-5xl overflow-hidden rounded-2xl border border-border bg-card/90 shadow-2xl shadow-black/25 md:grid-cols-[1.05fr_0.95fr]">
        <section className="relative hidden min-h-[560px] flex-col justify-between overflow-hidden border-r border-border p-10 md:flex">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_25%_30%,hsl(188_85%_53%/0.11),transparent_50%)]" />
          <div className="relative">
            <div className="flex items-center gap-3">
              <span className="flex h-11 w-11 items-center justify-center rounded-xl border border-primary/25 bg-primary/10 text-primary">
                <ShieldCheck className="h-6 w-6" />
              </span>
              <div>
                <p className="font-bold tracking-[0.16em]">VULNEXIS</p>
                <p className="mt-0.5 text-[10px] tracking-wide text-muted-foreground">SECURITY INTELLIGENCE</p>
              </div>
            </div>
            <div className="mt-24 max-w-sm">
              <p className="eyebrow text-primary">Discover. Analyze. Defend.</p>
              <h1 className="mt-4 text-4xl font-semibold leading-tight tracking-tight">
                Clarity for your
                <span className="block text-primary">security posture.</span>
              </h1>
              <p className="mt-4 text-sm leading-6 text-muted-foreground">
                Agent-less Windows and network security intelligence for teams that need actionable insight.
              </p>
            </div>
          </div>
          <div className="relative flex items-center justify-between border-t border-border pt-5 text-xs text-muted-foreground">
            <span>Agent-less Security Intelligence Platform</span>
            <Activity className="h-4 w-4 text-primary" />
          </div>
          <div className="pointer-events-none absolute bottom-28 right-10 h-48 w-48 rounded-full border border-primary/10" />
          <div className="pointer-events-none absolute bottom-36 right-18 h-32 w-32 rounded-full border border-primary/10" />
        </section>

        <section className="flex min-h-[560px] items-center justify-center p-6 sm:p-10">
          <Card className="w-full max-w-sm border-0 bg-transparent shadow-none">
            <CardHeader className="px-0 pb-7">
              <div className="mb-5 flex h-10 w-10 items-center justify-center rounded-lg border border-primary/20 bg-primary/10 text-primary md:hidden">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <p className="eyebrow">Secure access</p>
              <CardTitle className="mt-2 text-2xl">Welcome back</CardTitle>
              <p className="pt-2 text-sm text-muted-foreground">Sign in to your VULNEXIS workspace.</p>
            </CardHeader>
            <CardContent className="px-0">
              <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input id="username" autoComplete="username" placeholder="Enter your username" {...register("username")} />
                  {errors.username && (
                    <p className="text-xs text-destructive">{errors.username.message}</p>
                  )}
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="password">Password</Label>
                    <span className="text-[11px] text-muted-foreground">Authorized users only</span>
                  </div>
                  <Input id="password" type="password" autoComplete="current-password" placeholder="Enter your password" {...register("password")} />
                  {errors.password && (
                    <p className="text-xs text-destructive">{errors.password.message}</p>
                  )}
                </div>
                {error && <p className="text-sm text-destructive" role="alert">{error}</p>}
                <Button type="submit" className="h-10 w-full" disabled={isSubmitting}>
                  {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <>Sign in <ArrowUpRight className="h-4 w-4" /></>}
                </Button>
              </form>
              <p className="mt-8 border-t border-border pt-5 text-center text-[11px] leading-5 text-muted-foreground">
                Agent-less Windows Vulnerability &amp; Network Security Platform
              </p>
            </CardContent>
          </Card>
        </section>
      </div>
    </div>
  );
}
