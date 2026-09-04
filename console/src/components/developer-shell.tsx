"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ClipboardCheck, LayoutDashboard, LogOut, PlusCircle, ShieldCheck } from "lucide-react";
import type React from "react";

type DeveloperShellProps = {
  children: React.ReactNode;
  userEmail: string;
};

const navigation = [
  { name: "Activity", href: "/developer", icon: LayoutDashboard },
  { name: "Access Requests", href: "/developer/access-requests", icon: ClipboardCheck },
  { name: "New Tenant", href: "/developer/tenants", icon: PlusCircle },
];

export default function DeveloperShell({ children, userEmail }: DeveloperShellProps) {
  const pathname = usePathname();
  const router = useRouter();

  const handleLogout = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/login");
    router.refresh();
  };

  return (
    <div className="authclaw-console min-h-screen bg-[#FBFAF9] text-[#0E1726]">
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-72 border-r border-[#E6E9F0] bg-white md:block">
        <div className="flex h-16 items-center gap-2.5 border-b border-[#E6E9F0] px-6">
          <div className="flex h-9 w-9 items-center justify-center rounded-[10px] bg-[#0E1726]">
            <ShieldCheck className="h-5 w-5 text-white" />
          </div>
          <div>
            <p className="text-base font-bold tracking-wide text-[#0E1726]">AuthClaw</p>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-[#6B7488]">Developer Console</p>
          </div>
        </div>
        <nav className="space-y-1.5 px-4 py-6">
          {navigation.map((item) => {
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition ${
                  active
                    ? "border-l-2 border-[#6D28D9] bg-[#F1ECFE] text-[#6D28D9]"
                    : "text-[#475069] hover:bg-[#F5F7FA] hover:text-[#0E1726]"
                }`}
              >
                <item.icon className={`h-4 w-4 ${active ? "text-[#6D28D9]" : "text-[#6B7488]"}`} />
                {item.name}
              </Link>
            );
          })}
        </nav>
      </aside>

      <div className="min-h-screen md:pl-72">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-[#E6E9F0] bg-white/90 px-4 backdrop-blur md:px-8">
          <div className="flex items-center gap-2 md:hidden">
            <ShieldCheck className="h-5 w-5 text-[#0E1726]" />
            <span className="text-sm font-bold text-[#0E1726]">Developer Console</span>
          </div>
          <nav className="hidden items-center gap-2 md:flex">
            {navigation.map((item) => {
              const active = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`rounded-lg px-3 py-2 text-xs font-semibold transition ${
                    active ? "bg-[#F1ECFE] text-[#6D28D9]" : "text-[#475069] hover:bg-[#F5F7FA]"
                  }`}
                >
                  {item.name}
                </Link>
              );
            })}
          </nav>
          <div className="flex items-center gap-3">
            <span className="hidden max-w-[220px] truncate text-xs font-medium text-[#475069] sm:inline">{userEmail}</span>
            <button
              type="button"
              onClick={handleLogout}
              className="inline-flex items-center gap-2 rounded-lg border border-[#E6E9F0] bg-white px-3 py-2 text-xs font-semibold text-red-700 transition hover:bg-red-50"
            >
              <LogOut className="h-4 w-4" />
              Sign out
            </button>
          </div>
        </header>
        <main className="p-6 md:p-8">{children}</main>
      </div>
    </div>
  );
}
