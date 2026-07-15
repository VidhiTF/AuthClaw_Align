"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Building,
  Cable,
  ChevronDown,
  ClipboardCheck,
  Cloud,
  Cpu,
  LayoutDashboard,
  LogOut,
  Menu,
  MessageSquare,
  ScrollText,
  Settings,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";
import NotificationBell from "@/components/notification-bell";

interface ConsoleShellProps {
  children: React.ReactNode;
  userEmail: string;
  tenantId: string;
  tenantName: string;
  userRole: string;
}

const navigation = [
  { name: "Overview", href: "/overview", icon: LayoutDashboard, roles: ["owner", "admin", "viewer"] },
  { name: "Gateway", href: "/gateway", icon: Cpu, roles: ["owner", "admin"] },
  { name: "Compliance", href: "/compliance", icon: ShieldCheck, roles: ["owner", "admin", "viewer"] },
  { name: "Approvals", href: "/approvals", icon: ClipboardCheck, roles: ["owner", "admin", "viewer"] },
  { name: "Audit", href: "/audit", icon: ScrollText, roles: ["owner", "admin", "viewer"] },
  { name: "Agent & Remediation", href: "/agent", icon: MessageSquare, roles: ["owner", "admin", "viewer"] },
  { name: "Integrations", href: "/connect", icon: Cable, roles: ["owner", "admin"] },
  { name: "Policies & Guardrails", href: "/policies", icon: ShieldAlert, roles: ["owner", "admin"] },
  { name: "Risk & Red Teaming", href: "/risk", icon: ShieldAlert, roles: ["owner", "admin", "viewer"] },
  { name: "Evidence", href: "/evidence", icon: ScrollText, roles: ["owner", "admin", "viewer"] },
  { name: "Findings", href: "/findings", icon: ShieldAlert, roles: ["owner", "admin", "viewer"] },
  { name: "Cloud", href: "/aws", icon: Cloud, roles: ["owner", "admin"] },
  { name: "Settings", href: "/settings", icon: Settings, roles: ["owner", "admin"] },
];

export default function ConsoleShell({ children, userEmail, tenantId, tenantName, userRole }: ConsoleShellProps) {
  const pathname = usePathname();
  const router = useRouter();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);
  const normalizedRole = userRole?.toLowerCase() || "viewer";
  const allowedNavigation = navigation.filter((item) => item.roles.includes(normalizedRole));

  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
      router.push("/login");
      router.refresh();
    } catch (error) {
      console.error("Failed to log out:", error);
    }
  };

  const currentPage = pathname === "/notifications" ? "Notifications" : navigation.find((item) => pathname === item.href)?.name || "Overview";

  const navLinks = (onClick?: () => void) => (
    <>
      {allowedNavigation.map((item) => {
        const active = pathname === item.href;
        return (
          <Link
            key={item.name}
            href={item.href}
            onClick={onClick}
            className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
              active
                ? "bg-[#F1ECFE] text-[#6D28D9] border-l-2 border-[#6D28D9]"
                : "text-[#475069] hover:text-[#0E1726] hover:bg-[#F5F7FA]"
            }`}
          >
            <item.icon className={`w-4.5 h-4.5 ${active ? "text-[#6D28D9]" : "text-[#6B7488]"}`} />
            {item.name}
          </Link>
        );
      })}
    </>
  );

  return (
    <div className="authclaw-console min-h-screen bg-[#FBFAF9] text-[#0E1726] flex flex-col font-sans">
      <header className="md:hidden m-3 flex items-center justify-between rounded-[20px] border border-[#E6E9F0] bg-white px-4 py-3 shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-[10px] bg-[#6D28D9] flex items-center justify-center">
            <ShieldCheck className="w-4 h-4 text-white" />
          </div>
          <div>
            <span className="block font-bold text-sm text-[#0E1726]">AuthClaw</span>
            <span className="block text-[10px] uppercase tracking-wider text-[#6B7488]">Governance Layer</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <NotificationBell />
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="text-[#6B7488] hover:text-[#0E1726] focus:outline-none"
            aria-label="Toggle navigation"
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </header>

      <div className="flex flex-1 relative">
        <aside className="sticky top-4 m-4 mr-0 hidden h-[calc(100vh-2rem)] w-64 flex-col overflow-hidden rounded-[20px] border border-[#E6E9F0] bg-white shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)] md:flex">
          <div className="h-16 flex items-center gap-2.5 px-6 border-b border-[#E6E9F0]">
            <div className="w-8 h-8 rounded-[10px] bg-[#6D28D9] flex items-center justify-center shadow-[0_8px_20px_-8px_rgba(109,40,217,.6)]">
              <ShieldCheck className="w-4.5 h-4.5 text-white" />
            </div>
            <div>
              <span className="block font-bold text-base text-[#0E1726] tracking-wide">AuthClaw</span>
              <span className="block text-[10px] font-semibold uppercase tracking-wider text-[#6B7488]">AI Governance Layer</span>
            </div>
          </div>

          <nav className="min-h-0 flex-1 overflow-y-auto px-4 py-6 pr-3 space-y-1.5">{navLinks()}</nav>

          <div className="p-4 border-t border-[#E6E9F0] bg-[#F5F7FA]">
            <div className="flex items-center gap-2.5 px-2.5 py-2 rounded-[10px] bg-white border border-[#E6E9F0]">
              <Building className="w-4 h-4 text-[#6B7488] flex-shrink-0" />
              <div className="overflow-hidden">
                <p className="text-[10px] uppercase tracking-wider font-semibold text-[#6B7488]">Active Tenant</p>
                <p className="text-xs font-medium text-[#475069] truncate">{tenantName || tenantId}</p>
              </div>
            </div>
          </div>
        </aside>

        <div
          className={`fixed inset-0 z-50 flex transition-all duration-200 md:hidden ${
            mobileMenuOpen ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0"
          }`}
        >
            <div className="fixed inset-0 bg-black/30 backdrop-blur-sm" onClick={() => setMobileMenuOpen(false)} />
            <aside
              className={`relative m-3 flex h-[calc(100%-1.5rem)] w-64 max-w-xs flex-col rounded-[20px] border border-[#E6E9F0] bg-white shadow-2xl transition-all duration-200 ${
                mobileMenuOpen ? "translate-x-0 opacity-100" : "-translate-x-3 opacity-0"
              }`}
            >
              <div className="h-16 flex items-center justify-between px-6 border-b border-[#E6E9F0]">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-[10px] bg-[#6D28D9] flex items-center justify-center">
                    <ShieldCheck className="w-4.5 h-4.5 text-white" />
                  </div>
                  <span className="font-bold text-[#0E1726]">AuthClaw</span>
                </div>
                <button onClick={() => setMobileMenuOpen(false)} className="text-[#6B7488] hover:text-[#0E1726]" aria-label="Close navigation">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <nav className="min-h-0 flex-1 overflow-y-auto px-4 py-6 pr-3 space-y-1">{navLinks(() => setMobileMenuOpen(false))}</nav>

              <div className="p-4 border-t border-[#E6E9F0]">
                <div className="flex items-center gap-2.5 px-2 py-1.5 rounded bg-[#F5F7FA] mb-4">
                  <Building className="w-4 h-4 text-[#6B7488]" />
                  <div className="overflow-hidden">
                    <p className="text-[10px] uppercase font-semibold text-[#6B7488]">Tenant</p>
                    <p className="text-xs font-medium text-[#475069] truncate">{tenantName || tenantId}</p>
                  </div>
                </div>
                <button
                  onClick={handleLogout}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-red-400 hover:bg-red-500/10 text-sm font-medium transition"
                >
                  <LogOut className="w-4 h-4" />
                  Sign Out
                </button>
              </div>
            </aside>
          </div>

        <div className="flex-1 flex flex-col min-w-0 bg-[#FBFAF9]">
          <header className="sticky top-4 z-30 mx-4 mt-4 hidden h-14 items-center justify-between rounded-[20px] border border-[#E6E9F0] bg-white/90 px-6 shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)] backdrop-blur-md md:flex">
            <div className="flex items-center gap-3">
              <span className="text-[#6B7488] text-sm">Governance Layer</span>
              <span className="text-[#A8B0C0]">/</span>
              <span className="text-[#0E1726] text-sm font-medium">{currentPage}</span>
            </div>

            <div className="flex items-center gap-2">
              <NotificationBell />
              <div className="relative">
              <button
                onClick={() => setProfileDropdownOpen(!profileDropdownOpen)}
                className="flex items-center gap-2.5 px-3 py-1.5 rounded-[10px] border border-[#E6E9F0] bg-white hover:bg-[#F5F7FA] hover:border-[#A78BFA] transition-all duration-150"
              >
                <div className="w-6 h-6 rounded-full bg-[#F1ECFE] border border-[#A78BFA] flex items-center justify-center text-[10px] font-bold text-[#6D28D9]">
                  {userEmail.slice(0, 2).toUpperCase()}
                </div>
                <span className="text-xs font-medium text-[#475069]">{userEmail}</span>
                <ChevronDown className={`w-3.5 h-3.5 text-[#6B7488] transition-transform duration-200 ${profileDropdownOpen ? "rotate-180" : ""}`} />
              </button>

              <div
                className={`fixed inset-0 z-30 ${profileDropdownOpen ? "pointer-events-auto" : "pointer-events-none"}`}
                onClick={() => setProfileDropdownOpen(false)}
              />
              <div
                className={`absolute right-0 z-40 mt-2 w-48 origin-top-right rounded-[10px] border border-[#E6E9F0] bg-white py-1 shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)] transition-all duration-200 ${
                  profileDropdownOpen ? "pointer-events-auto translate-y-0 scale-100 opacity-100" : "pointer-events-none -translate-y-1 scale-95 opacity-0"
                }`}
              >
                    <div className="px-4 py-2 border-b border-[#E6E9F0]">
                      <p className="text-[10px] font-semibold uppercase text-[#6B7488] tracking-wider">Signed In As</p>
                      <p className="text-xs text-[#475069] truncate font-medium mt-0.5">{userEmail}</p>
                      <p className="text-[10px] text-[#6B7488] capitalize mt-0.5">{normalizedRole}</p>
                    </div>
                    <button
                      onClick={handleLogout}
                      className="w-full flex items-center gap-2 px-4 py-2.5 text-left text-sm text-red-400 hover:bg-red-500/5 hover:text-red-300 transition-colors duration-150"
                    >
                      <LogOut className="w-4 h-4" />
                      Sign Out
                    </button>
                  </div>
              </div>
            </div>
          </header>

          <main className="flex-1 overflow-auto p-6 md:p-8">{children}</main>
        </div>
      </div>
    </div>
  );
}
