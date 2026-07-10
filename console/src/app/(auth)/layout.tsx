import React from 'react';

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-[#08152B] flex flex-col items-center justify-center p-4 text-slate-100">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_10%,rgba(233,169,60,0.12),transparent_32%),radial-gradient(circle_at_80%_0%,rgba(109,40,217,0.18),transparent_36%)]" />
      <div className="relative w-full max-w-md bg-[#0B1F3F]/90 border border-white/10 rounded-2xl shadow-2xl p-8">
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 bg-gradient-to-br from-violet-700 to-[#1B3663] rounded-xl flex items-center justify-center mb-4 shadow-lg shadow-violet-950/40">
            <span className="text-white font-bold text-xl">AC</span>
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">AuthClaw</h1>
          <p className="text-slate-300 text-sm mt-1">The runtime layer for AI compliance</p>
        </div>
        {children}
      </div>
    </div>
  );
}
