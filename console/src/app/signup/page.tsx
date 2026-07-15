"use client";

import React, { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowRight,
  Building2,
  CheckCircle2,
  Clipboard,
  KeyRound,
  Mail,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { flashCopy } from "@/lib/clipboard";
import { apiErrorMessage, getErrorMessage } from "@/lib/errors";

interface SignupResponse {
  signup_id: string;
  email: string;
  tenant_name: string;
  expires_at: string;
  delivery: string;
  next_resend_at: string;
  dev_otp?: string;
}

interface VerifyResponse {
  tenant_id: string;
  tenant_name: string;
  user_id: string;
  email: string;
  role: string;
  api_key: string;
  gateway_url: string;
  provider: string;
  model: string;
  powershell_snippet: string;
  curl_snippet: string;
}

function isUuid(value: string | null): value is string {
  return Boolean(
    value &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
  );
}

function SignupPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const inviteId = searchParams.get("invite");
  const isInviteMode = Boolean(inviteId);
  const [tenantName, setTenantName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [signup, setSignup] = useState<SignupResponse | null>(null);
  const [verified, setVerified] = useState<VerifyResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const step = useMemo(() => {
    if (verified) return 3;
    if (isInviteMode) return 2;
    if (signup) return 2;
    return 1;
  }, [isInviteMode, signup, verified]);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const nextResendAt = signup?.next_resend_at;
  const resendSecondsRemaining = nextResendAt
    ? Math.max(0, Math.ceil((new Date(nextResendAt).getTime() - now) / 1000))
    : 0;

  const requestOtp = async (event: React.FormEvent) => {
    event.preventDefault();
    if (password.length < 12) {
      setError("Password must be at least 12 characters.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      window.sessionStorage.removeItem("authclaw_onboarding_result");
      const response = await fetch("/api/onboarding/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, tenant_name: tenantName }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(apiErrorMessage(data, "Could not start signup"));
      }
      setSignup(data);
      setOtp("");
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Could not start signup"));
    } finally {
      setLoading(false);
    }
  };

  const verifyOtp = async (event: React.FormEvent) => {
    event.preventDefault();
    const signupId = signup?.signup_id || inviteId;
    if (!signupId) return;
    if (password.length < 12) {
      setError("Password must be at least 12 characters.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (isInviteMode && !isUuid(inviteId)) {
      setError("Invite link is incomplete or invalid. Ask the owner to copy the full invite link again.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("/api/onboarding/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ signup_id: signupId, otp, password }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(apiErrorMessage(data, "Could not verify code"));
      }
      setVerified(data);
      if (isInviteMode) {
        window.sessionStorage.removeItem("authclaw_onboarding_result");
        router.push("/overview");
      } else {
        window.sessionStorage.setItem("authclaw_onboarding_result", JSON.stringify(data));
        router.push("/connect?onboarding=1");
      }
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Could not verify code"));
    } finally {
      setLoading(false);
    }
  };

  const resendOtp = async () => {
    if (!signup) return;
    setResending(true);
    setError(null);
    try {
      const response = await fetch("/api/onboarding/resend", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ signup_id: signup.signup_id }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(apiErrorMessage(data, "Could not resend code"));
      }
      setSignup((current) => current ? { ...current, ...data } : current);
      setOtp("");
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Could not resend code"));
    } finally {
      setResending(false);
    }
  };

  const copyText = async (label: string, value: string) => {
    await flashCopy(value, setCopied, label, null, 1600);
  };

  return (
    <main className="min-h-screen bg-[#FBFAF9] text-[#0E1726] font-sans">
      <div className="mx-auto flex min-h-screen w-full max-w-5xl flex-col justify-center px-5 py-10">
        <div className="mb-8 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-[10px] bg-[#6D28D9]">
              <ShieldCheck className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight">AuthClaw Lite</h1>
              <p className="text-xs text-[#6B7488]">Create a protected AI gateway tenant</p>
            </div>
          </div>
          <Link href="/login" className="text-xs font-semibold text-[#6D28D9] hover:text-[#7C3AED]">
            Sign in
          </Link>
        </div>

        <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
          <aside className="rounded-[14px] border border-[#E6E9F0] bg-white p-5 shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
            {[
              ["Email OTP", isInviteMode ? "Verify tenant invite" : "Verify account ownership"],
              ["Tenant Setup", isInviteMode ? "Join existing tenant" : "Create tenant, route, key, policy"],
              ["Connect Provider", isInviteMode ? "Open tenant console" : "Save upstream Gemini/OpenAI key"],
            ].map(([title, subtitle], index) => {
              const active = step === index + 1;
              const complete = step > index + 1;
              return (
                <div key={title} className="flex gap-3 pb-5 last:pb-0">
                  <div
                    className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border text-xs font-bold ${
                      complete
                        ? "border-emerald-400 bg-emerald-400 text-slate-950"
                        : active
                          ? "border-indigo-400 bg-indigo-500 text-white"
                        : "border-[#E6E9F0] text-[#6B7488]"
                    }`}
                  >
                    {complete ? <CheckCircle2 className="h-4 w-4" /> : index + 1}
                  </div>
                  <div>
                    <p className={`text-sm font-semibold ${active ? "text-[#0E1726]" : "text-[#475069]"}`}>{title}</p>
                    <p className="text-xs text-[#6B7488]">{subtitle}</p>
                  </div>
                </div>
              );
            })}
          </aside>

          <section className="rounded-[14px] border border-[#E6E9F0] bg-white p-6 shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
            {error && (
              <div className="mb-5 flex items-center gap-3 rounded-lg border border-red-500/25 bg-red-500/10 p-3 text-xs text-red-200">
                <ShieldAlert className="h-4 w-4 text-red-300" />
                {error}
              </div>
            )}

            {!signup && !isInviteMode && (
              <form onSubmit={requestOtp} className="space-y-5" autoComplete="off">
                <div>
                  <h2 className="text-lg font-bold text-[#0E1726]">Create Tenant</h2>
                  <p className="mt-1 text-sm text-[#6B7488]">Start with email verification, then AuthClaw creates your tenant gateway.</p>
                </div>

                <label className="block">
                  <span className="mb-2 block text-xs font-semibold uppercase tracking-wider text-[#475069]">Work Email</span>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#6B7488]" />
                    <input
                      type="email"
                      name="authclaw_signup_work_email"
                      autoComplete="off"
                      required
                      value={email}
                      onChange={(event) => setEmail(event.target.value)}
                      className="w-full rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] py-2.5 pl-10 pr-4 text-sm text-[#0E1726] outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
                      placeholder="you@company.com"
                    />
                  </div>
                </label>

                <label className="block">
                  <span className="mb-2 block text-xs font-semibold uppercase tracking-wider text-[#475069]">Tenant Name</span>
                  <div className="relative">
                    <Building2 className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#6B7488]" />
                    <input
                      type="text"
                      name="authclaw_signup_tenant_name"
                      autoComplete="organization"
                      required
                      value={tenantName}
                      onChange={(event) => setTenantName(event.target.value)}
                      className="w-full rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] py-2.5 pl-10 pr-4 text-sm text-[#0E1726] outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
                      placeholder="Acme Support"
                    />
                  </div>
                </label>

                <label className="block">
                  <span className="mb-2 block text-xs font-semibold uppercase tracking-wider text-[#475069]">Password</span>
                  <div className="relative">
                    <KeyRound className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#6B7488]" />
                    <input
                      type="password"
                      name="authclaw_signup_password"
                      autoComplete="new-password"
                      required
                      minLength={12}
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      className="w-full rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] py-2.5 pl-10 pr-4 text-sm text-[#0E1726] outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
                      placeholder="At least 12 characters"
                    />
                  </div>
                </label>

                <label className="block">
                  <span className="mb-2 block text-xs font-semibold uppercase tracking-wider text-[#475069]">Confirm Password</span>
                  <div className="relative">
                    <KeyRound className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#6B7488]" />
                    <input
                      type="password"
                      name="authclaw_signup_confirm_password"
                      autoComplete="new-password"
                      required
                      minLength={12}
                      value={confirmPassword}
                      onChange={(event) => setConfirmPassword(event.target.value)}
                      className="w-full rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] py-2.5 pl-10 pr-4 text-sm text-[#0E1726] outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
                      placeholder="Repeat password"
                    />
                  </div>
                </label>

                <button
                  type="submit"
                  disabled={loading}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-[10px] bg-[#6D28D9] px-4 py-2.5 text-sm font-semibold text-white hover:bg-[#7C3AED] disabled:opacity-60"
                >
                  {loading ? "Sending code..." : "Send Verification Code"}
                  <ArrowRight className="h-4 w-4" />
                </button>
              </form>
            )}

            {(signup || isInviteMode) && !verified && (
              <form onSubmit={verifyOtp} className="space-y-5" autoComplete="off">
                <div>
                  <h2 className="text-lg font-bold text-[#0E1726]">{isInviteMode ? "Verify Tenant Invite" : "Verify Email"}</h2>
                  <p className="mt-1 text-sm text-[#6B7488]">
                    {isInviteMode ? "Enter the 6-digit code sent to your email." : `Enter the 6-digit code sent to ${signup?.email}.`}
                  </p>
                </div>

                <div className="rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] p-3 text-xs text-[#475069]">
                  {isInviteMode
                    ? "Check your inbox and spam folder for the tenant invite code."
                    : signup?.delivery === "local_outbox"
                      ? "Local delivery wrote the verification email to .authclaw/email-outbox.jsonl."
                      : "Check your inbox and spam folder for the verification code."}
                </div>

                {isInviteMode && (
                  <>
                    <label className="block">
                      <span className="mb-2 block text-xs font-semibold uppercase tracking-wider text-[#475069]">Password</span>
                      <input
                        type="password"
                        name="authclaw_invite_password"
                        autoComplete="new-password"
                        required
                        minLength={12}
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        className="w-full rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] px-4 py-2.5 text-sm text-[#0E1726] outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
                        placeholder="At least 12 characters"
                      />
                    </label>
                    <label className="block">
                      <span className="mb-2 block text-xs font-semibold uppercase tracking-wider text-[#475069]">Confirm Password</span>
                      <input
                        type="password"
                        name="authclaw_invite_confirm_password"
                        autoComplete="new-password"
                        required
                        minLength={12}
                        value={confirmPassword}
                        onChange={(event) => setConfirmPassword(event.target.value)}
                        className="w-full rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] px-4 py-2.5 text-sm text-[#0E1726] outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
                        placeholder="Repeat password"
                      />
                    </label>
                  </>
                )}

                <label className="block">
                  <span className="mb-2 block text-xs font-semibold uppercase tracking-wider text-[#475069]">Verification Code</span>
                  <input
                    inputMode="numeric"
                    name="authclaw_signup_otp"
                    autoComplete="one-time-code"
                    required
                    minLength={6}
                    maxLength={6}
                    value={otp}
                    onChange={(event) => setOtp(event.target.value.replace(/\D/g, "").slice(0, 6))}
                    className="w-full rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] px-4 py-3 text-center font-mono text-lg tracking-[0.35em] text-[#0E1726] outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
                    placeholder="000000"
                  />
                </label>

                <button
                  type="submit"
                  disabled={loading || otp.length !== 6}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-[10px] bg-[#6D28D9] px-4 py-2.5 text-sm font-semibold text-white hover:bg-[#7C3AED] disabled:opacity-60"
                >
                  {loading ? (isInviteMode ? "Joining tenant..." : "Creating tenant...") : (isInviteMode ? "Verify and Join Tenant" : "Verify and Create Tenant")}
                  <ShieldCheck className="h-4 w-4" />
                </button>

                {signup && (
                <div className="flex flex-col gap-2 border-t border-[#E6E9F0] pt-4 sm:flex-row sm:items-center sm:justify-between">
                  <p className="text-xs text-[#6B7488]">
                    Code expires {new Date(signup.expires_at).toLocaleTimeString()}.
                  </p>
                  <button
                    type="button"
                    onClick={() => void resendOtp()}
                    disabled={loading || resending || resendSecondsRemaining > 0}
                    className="inline-flex items-center justify-center rounded-[10px] border border-[#E6E9F0] px-3 py-2 text-xs font-semibold text-[#475069] hover:bg-[#F5F7FA] disabled:opacity-60"
                  >
                    {resending
                      ? "Resending..."
                      : resendSecondsRemaining > 0
                        ? `Resend in ${resendSecondsRemaining}s`
                        : "Resend Code"}
                  </button>
                </div>
                )}
              </form>
            )}

            {verified && (
              <div className="space-y-5">
                <div>
                  <h2 className="text-lg font-bold text-[#0E1726]">Tenant Ready</h2>
                  <p className="mt-1 text-sm text-[#6B7488]">Your gateway key, starter policy, and default Gemini route are ready.</p>
                </div>

                <div className="rounded-lg border border-emerald-400/25 bg-emerald-400/10 p-3 text-sm text-emerald-100">
                  Signed in as {verified.email} for {verified.tenant_name}.
                </div>

                <div>
                  <div className="mb-2 flex items-center justify-between">
                    <span className="text-xs font-semibold uppercase tracking-wider text-[#475069]">AuthClaw Gateway Key</span>
                    <button
                      type="button"
                      onClick={() => copyText("key", verified.api_key)}
                      className="inline-flex items-center gap-1 text-xs font-semibold text-[#6D28D9] hover:text-[#7C3AED]"
                    >
                      <Clipboard className="h-3.5 w-3.5" />
                      {copied === "key" ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <pre className="overflow-x-auto rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] p-3 text-xs text-[#0E1726]">
                    {verified.api_key}
                  </pre>
                </div>

                <div>
                  <div className="mb-2 flex items-center justify-between">
                    <span className="text-xs font-semibold uppercase tracking-wider text-[#475069]">PowerShell Test Request</span>
                    <button
                      type="button"
                      onClick={() => copyText("powershell", verified.powershell_snippet)}
                      className="inline-flex items-center gap-1 text-xs font-semibold text-[#6D28D9] hover:text-[#7C3AED]"
                    >
                      <Clipboard className="h-3.5 w-3.5" />
                      {copied === "powershell" ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <pre className="max-h-56 overflow-auto rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] p-3 text-xs text-[#0E1726]">
                    {verified.powershell_snippet}
                  </pre>
                </div>

                <button
                  type="button"
                  onClick={() => router.push("/connect")}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-[10px] bg-[#6D28D9] px-4 py-2.5 text-sm font-semibold text-white hover:bg-[#7C3AED]"
                >
                  Continue to Provider Key Vault
                  <KeyRound className="h-4 w-4" />
                </button>
              </div>
            )}
          </section>
        </div>
      </div>
    </main>
  );
}

export default function SignupPage() {
  return (
    <Suspense fallback={<main className="min-h-screen bg-[#FBFAF9] text-[#0E1726]" />}>
      <SignupPageContent />
    </Suspense>
  );
}
