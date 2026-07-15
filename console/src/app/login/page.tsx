"use client";

import React, { useState, useSyncExternalStore } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Building2, Lock, Mail, ShieldAlert, ShieldCheck } from "lucide-react";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [tenantName, setTenantName] = useState("");
  const [resetMode, setResetMode] = useState<"login" | "request" | "confirm">("login");
  const [resetSignupId, setResetSignupId] = useState("");
  const [resetOtp, setResetOtp] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(() => {
    if (typeof window === "undefined") return null;
    return new URLSearchParams(window.location.search).get("sso_error");
  });
  const [message, setMessage] = useState<string | null>(null);
  const hydrated = useSyncExternalStore(() => () => {}, () => true, () => false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setMessage(null);

    try {
      window.sessionStorage.removeItem("authclaw_onboarding_result");
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, tenantName: tenantName || undefined }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || data.detail || "Authentication failed");
      }

      router.push("/connect");
      router.refresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  const startSso = () => {
    setError(null);
    setMessage(null);
    const params = new URLSearchParams();
    if (tenantName.trim()) params.set("tenantName", tenantName.trim());
    window.location.href = `/api/auth/oidc/start?${params.toString()}`;
  };

  const requestPasswordReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setMessage(null);
    try {
      const response = await fetch("/api/auth/password-reset/request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, tenantName: tenantName || undefined }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || data.detail || "Could not start password reset");
      }
      if (data.signup_id) {
        setResetSignupId(data.signup_id);
        setResetMode("confirm");
        setMessage(data.delivery === "local_outbox"
          ? "Reset email written to .authclaw/email-outbox.jsonl."
          : "Check your email for the password reset code.");
      } else {
        setResetMode("login");
        setMessage("If that account exists, a reset code has been sent.");
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Could not start password reset");
    } finally {
      setLoading(false);
    }
  };

  const confirmPasswordReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setMessage(null);
    try {
      if (newPassword.length < 12) throw new Error("Password must be at least 12 characters.");
      if (newPassword !== confirmPassword) throw new Error("Passwords do not match.");
      const response = await fetch("/api/auth/password-reset/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ signup_id: resetSignupId, otp: resetOtp, password: newPassword }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || data.detail || "Could not reset password");
      }
      setPassword("");
      setResetOtp("");
      setNewPassword("");
      setConfirmPassword("");
      setResetSignupId("");
      setResetMode("login");
      setMessage("Password updated. Sign in with your new password.");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Could not reset password");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen w-full bg-[#FBFAF9] text-[#0E1726] font-sans">
      <div className="mx-auto flex min-h-screen w-full max-w-6xl items-center justify-center px-5 py-12">
      <div className="w-full max-w-[440px] rounded-[20px] border border-[#E6E9F0] bg-white px-6 py-8 shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
        <div className="flex flex-col items-center mb-8 text-center">
          <div className="flex items-center justify-center w-12 h-12 rounded-[14px] bg-[#6D28D9] shadow-[0_8px_20px_-8px_rgba(109,40,217,.6)] mb-3">
            <ShieldCheck className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-[#0E1726]">
            AuthClaw
          </h1>
          <p className="text-xs text-[#6B7488] mt-1">
            Sign in with your console account
          </p>
        </div>

        {error && (
          <div className="flex items-center gap-3 p-3.5 mb-6 rounded-[10px] bg-red-50 border border-red-200 text-red-700 text-xs">
            <ShieldAlert className="w-4.5 h-4.5 text-red-600 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {message && (
          <div className="mb-6 rounded-[10px] border border-emerald-200 bg-emerald-50 p-3.5 text-xs text-emerald-800">
            {message}
          </div>
        )}

        {resetMode === "login" && (
        <form onSubmit={handleSubmit} className="space-y-5" autoComplete="off">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-[#475069] mb-2">
              Email Address
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#6B7488]">
                <Mail className="w-4 h-4" />
              </span>
              <input
                type="email"
                required
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@authclaw.com"
                className="w-full pl-10 pr-4 py-2.5 rounded-[10px] bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-sm placeholder-[#6B7488] focus:outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-[#475069] mb-2">
              Password
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#6B7488]">
                <Lock className="w-4 h-4" />
              </span>
              <input
                type="password"
                required
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                className="w-full pl-10 pr-4 py-2.5 rounded-[10px] bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-sm placeholder-[#6B7488] focus:outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
              />
            </div>
            <p className="text-[10px] text-[#6B7488] mt-1.5">Gateway API keys are no longer accepted for console login.</p>
            <button
              type="button"
              onClick={() => {
                setError(null);
                setMessage(null);
                setResetMode("request");
              }}
              className="mt-2 text-xs font-semibold text-[#6D28D9] hover:text-[#7C3AED]"
            >
              Forgot password?
            </button>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-[#475069] mb-2">
              Tenant Name
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#6B7488]">
                <Building2 className="w-4 h-4" />
              </span>
              <input
                type="text"
                autoComplete="off"
                value={tenantName}
                onChange={(e) => setTenantName(e.target.value)}
                placeholder="Only needed if your email has multiple tenants"
                className="w-full pl-10 pr-4 py-2.5 rounded-[10px] bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-sm placeholder-[#6B7488] focus:outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading || !hydrated}
            className="relative w-full py-2.5 rounded-[10px] bg-[#6D28D9] text-white font-semibold text-sm shadow-[0_8px_20px_-8px_rgba(109,40,217,.6)] hover:bg-[#7C3AED] active:scale-[0.99] disabled:opacity-50 disabled:pointer-events-none transition-all duration-200"
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <svg className="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                Authenticating...
              </span>
            ) : (
              "Sign In"
            )}
          </button>

          <button
            type="button"
            onClick={startSso}
            disabled={loading}
            className="w-full rounded-[10px] border border-[#E6E9F0] bg-white py-2.5 text-sm font-semibold text-[#475069] transition hover:bg-[#F5F7FA] disabled:opacity-50"
          >
            Continue with Enterprise SSO
          </button>
        </form>
        )}

        {resetMode === "request" && (
          <form onSubmit={requestPasswordReset} className="space-y-5" autoComplete="off">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-[#475069] mb-2">
                Email Address
              </label>
              <input
                type="email"
                required
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-2.5 rounded-[10px] bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-sm placeholder-[#6B7488] focus:outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
                placeholder="you@company.com"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-[#475069] mb-2">
                Tenant Name
              </label>
              <input
                type="text"
                autoComplete="off"
                value={tenantName}
                onChange={(e) => setTenantName(e.target.value)}
                className="w-full px-4 py-2.5 rounded-[10px] bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-sm placeholder-[#6B7488] focus:outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
                placeholder="Only needed if your email has multiple tenants"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="relative w-full py-2.5 rounded-[10px] bg-[#6D28D9] text-white font-semibold text-sm shadow-[0_8px_20px_-8px_rgba(109,40,217,.6)] hover:bg-[#7C3AED] disabled:opacity-50"
            >
              {loading ? "Sending reset code..." : "Send reset code"}
            </button>
            <button
              type="button"
              onClick={() => setResetMode("login")}
              className="w-full text-xs font-semibold text-[#6D28D9] hover:text-[#7C3AED]"
            >
              Back to sign in
            </button>
          </form>
        )}

        {resetMode === "confirm" && (
          <form onSubmit={confirmPasswordReset} className="space-y-5">
            <input
              inputMode="numeric"
              required
              autoComplete="one-time-code"
              minLength={6}
              maxLength={6}
              value={resetOtp}
              onChange={(e) => setResetOtp(e.target.value.replace(/\D/g, "").slice(0, 6))}
              className="w-full rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] px-4 py-3 text-center font-mono text-lg tracking-[0.35em] text-[#0E1726] outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
              placeholder="000000"
            />
            <input
              type="password"
              required
              autoComplete="new-password"
              minLength={12}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full px-4 py-2.5 rounded-[10px] bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-sm placeholder-[#6B7488] focus:outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
              placeholder="New password"
            />
            <input
              type="password"
              required
              autoComplete="new-password"
              minLength={12}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full px-4 py-2.5 rounded-[10px] bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-sm placeholder-[#6B7488] focus:outline-none focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]"
              placeholder="Confirm new password"
            />
            <button
              type="submit"
              disabled={loading || resetOtp.length !== 6}
              className="relative w-full py-2.5 rounded-[10px] bg-[#6D28D9] text-white font-semibold text-sm shadow-[0_8px_20px_-8px_rgba(109,40,217,.6)] hover:bg-[#7C3AED] disabled:opacity-50"
            >
              {loading ? "Updating password..." : "Update password"}
            </button>
          </form>
        )}

        <div className="mt-6 pt-5 border-t border-[#E6E9F0] text-center">
          <p className="text-xs text-[#6B7488]">
            New to AuthClaw?{" "}
            <Link href="/signup" className="font-semibold text-[#6D28D9] hover:text-[#7C3AED]">
              Create a tenant
            </Link>
          </p>
        </div>
      </div>
      </div>
    </main>
  );
}
