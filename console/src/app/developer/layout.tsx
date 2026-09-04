import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import type React from "react";
import DeveloperShell from "@/components/developer-shell";

export default async function DeveloperLayout({ children }: { children: React.ReactNode }) {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get("authclaw_session")?.value;
  if (!sessionToken) redirect("/login?developer=1");

  const response = await fetch(
    `${process.env.API_URL || "http://localhost:8000"}/v1/auth/me`,
    { headers: { Authorization: `Bearer ${sessionToken}` }, cache: "no-store" },
  );
  if (!response.ok) redirect("/login?developer=1");

  const principal = await response.json();
  const scopes = Array.isArray(principal.scopes) ? principal.scopes : [];
  const isAuthClawDeveloper = (
    principal.tenant_id === null
    && principal.role === "platform_admin"
    && principal.is_active === true
    && String(principal.platform_role || "NONE").toUpperCase() === "ADMIN"
    && scopes.includes("platform.admin")
  );
  if (!isAuthClawDeveloper) redirect("/login?developer=1");

  return <DeveloperShell userEmail={principal.email}>{children}</DeveloperShell>;
}
