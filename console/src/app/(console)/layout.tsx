import React from "react";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import ConsoleShell from "@/components/console-shell";
import { authenticateSessionCookie } from "@/lib/session-auth";

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get("authclaw_session")?.value;
  const session = authenticateSessionCookie(sessionToken);
  if (!session) redirect("/login");

  let userEmail = "admin@authclaw.com";
  const tenantId = session.tenantId;
  let tenantName = "Default Tenant";
  const userRole = session.role;

  try {
    const payload = JSON.parse(sessionToken!);
    userEmail = payload.email || userEmail;
    tenantName = payload.tenantName || tenantName;
  } catch {
    redirect("/login");
  }

  return (
    <ConsoleShell userEmail={userEmail} tenantId={tenantId} tenantName={tenantName} userRole={userRole}>
      {children}
    </ConsoleShell>
  );
}
