import React from "react";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import ConsoleShell from "@/components/console-shell";

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get("authclaw_session")?.value;
  if (!sessionToken) redirect("/login");
  const response = await fetch(
    `${process.env.API_URL || "http://localhost:8000"}/v1/auth/me`,
    { headers: { Authorization: `Bearer ${sessionToken}` }, cache: "no-store" },
  );
  if (!response.ok) redirect("/login");
  const principal = await response.json();
  const userEmail = principal.email;
  const tenantId = principal.tenant_id;
  const tenantName = "Current Tenant";
  const userRole = principal.role;

  return (
    <ConsoleShell userEmail={userEmail} tenantId={tenantId} tenantName={tenantName} userRole={userRole}>
      {children}
    </ConsoleShell>
  );
}
