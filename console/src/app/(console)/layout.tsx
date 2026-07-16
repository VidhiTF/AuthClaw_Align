import React from "react";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import ConsoleShell from "@/components/console-shell";

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get("authclaw_session")?.value;

  if (!sessionToken) {
    redirect("/login");
  }

  let userEmail = "admin@authclaw.com";
  let tenantId = "default-tenant";
  let tenantName = "Default Tenant";
  let userRole = "viewer";

  try {
    const payload = JSON.parse(sessionToken);
    userEmail = payload.email || userEmail;
    tenantId = payload.tenantId || tenantId;
    tenantName = payload.tenantName || tenantName;
    userRole = payload.role || userRole;
  } catch {
    redirect("/login");
  }

  return (
    <ConsoleShell userEmail={userEmail} tenantId={tenantId} tenantName={tenantName} userRole={userRole}>
      {children}
    </ConsoleShell>
  );
}
