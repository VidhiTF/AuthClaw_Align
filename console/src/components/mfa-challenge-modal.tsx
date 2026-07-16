"use client";

import { KeyRound, Loader2, Lock } from "lucide-react";
import React from "react";
import ModalShell from "./modal-shell";

type MfaChallengeModalProps = {
  code: string;
  setCode: (value: string) => void;
  busy: boolean;
  error?: string | null;
  onClose: () => void;
  onSubmit: (event: React.FormEvent) => void;
  accentClass?: string;
  description: string;
  submitLabel: string;
  busyLabel?: string;
  requireCode?: boolean;
};

export default function MfaChallengeModal({
  code,
  setCode,
  busy,
  error,
  onClose,
  onSubmit,
  accentClass = "text-indigo-400",
  description,
  submitLabel,
  busyLabel = "Verifying...",
  requireCode = false,
}: MfaChallengeModalProps) {
  const inputFocusClass = accentClass === "text-emerald-400" ? "focus:border-emerald-500/80" : "focus:border-indigo-500/80";

  return (
    <ModalShell
      title={
        <span className="flex items-center gap-1.5">
          <Lock className={`w-4 h-4 ${accentClass}`} />
          MFA Identity Authorization
        </span>
      }
      onClose={onClose}
      error={error}
      glowClass={accentClass === "text-emerald-400" ? "bg-emerald-500/5" : "bg-indigo-500/5"}
    >
      <form onSubmit={onSubmit} className="space-y-4">
        <p className="text-xs text-[#6B7488] leading-relaxed">{description}</p>
        <div>
          <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488] mb-1.5">
            TOTP Code / Backup Code
          </label>
          <div className="relative">
            <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#6B7488]">
              <KeyRound className="w-4 h-4" />
            </span>
            <input
              type="text"
              required={requireCode}
              value={code}
              onChange={(event) => setCode(event.target.value)}
              placeholder="Enter code"
              autoFocus
              className={`w-full pl-10 pr-4 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs font-mono placeholder-[#A8B0C0] focus:outline-none ${inputFocusClass} transition text-center tracking-widest`}
            />
          </div>
        </div>
        <div className="pt-4 border-t border-[#E6E9F0] flex justify-end gap-2.5">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-[#F5F7FA] hover:bg-[#F5F7FA] border border-[#E6E9F0] text-[#475069] font-semibold text-xs transition"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={busy || (requireCode && !code)}
            className={`px-4 py-2 rounded-lg ${accentClass === "text-emerald-400" ? "bg-emerald-600 hover:bg-emerald-500" : "bg-indigo-600 hover:bg-indigo-500"} text-white font-semibold text-xs shadow-lg transition disabled:opacity-50 flex items-center gap-1.5`}
          >
            {busy ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                {busyLabel}
              </>
            ) : (
              submitLabel
            )}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}
