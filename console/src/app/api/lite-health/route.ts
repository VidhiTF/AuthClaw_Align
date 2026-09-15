import { NextResponse } from "next/server";
import { agentFetch, backendFetch, getSessionContext, handleApiError } from "@/lib/api-client";

interface HealthItem {
  key: string;
  label: string;
  ok: boolean;
  detail: string;
}

export async function GET() {
  try {
    const context = await getSessionContext();
    if ("response" in context) return context.response;
    const items: HealthItem[] = [];

    const gatewayUrl =
      process.env.GATEWAY_INTERNAL_URL ||
      process.env.NEXT_PUBLIC_GATEWAY_URL ||
      "http://localhost:8080";
    const backendUrl = process.env.API_URL || "http://localhost:8000";

    try {
      const backendRes = await fetch(`${backendUrl}/health`, { cache: "no-store" });
      const backendHealth = backendRes.ok ? await backendRes.json() : null;
      const secretStatus = backendHealth?.secret_management;
      items.push({
        key: "secret_management",
        label: "Secret management configured",
        ok: Boolean(secretStatus?.configured),
        detail: secretStatus
          ? (secretStatus.configured ? "Secret management configured" : "Secret management not configured")
          : `Backend returned ${backendRes.status}`,
      });
    } catch {
      items.push({
        key: "secret_management",
        label: "Secret management configured",
        ok: false,
        detail: "Backend health check unavailable",
      });
    }

    try {
      const gatewayRes = await fetch(`${gatewayUrl}/health`, { cache: "no-store" });
      items.push({
        key: "gateway",
        label: "Gateway reachable",
        ok: gatewayRes.ok,
        detail: gatewayRes.ok ? "Gateway reachable" : `Gateway returned ${gatewayRes.status}`,
      });
    } catch {
      items.push({
        key: "gateway",
        label: "Gateway reachable",
        ok: false,
        detail: "Gateway health check unavailable",
      });
    }

    try {
      const readiness = await agentFetch("/api/v1/agent/health/ready");
      items.push({
        key: "agent",
        label: "Agent service authenticated",
        ok: readiness?.status === "ready",
        detail: readiness?.status === "ready"
          ? "Canonical agent API is ready"
          : "Canonical agent API is not ready",
      });
    } catch {
      items.push({
        key: "agent",
        label: "Agent service authenticated",
        ok: false,
        detail: "Agent readiness check unavailable",
      });
    }

    try {
      const routes = await backendFetch("/v1/gateways");
      items.push({
        key: "routes",
        label: "Provider route configured",
        ok: Array.isArray(routes) && routes.length > 0,
        detail: Array.isArray(routes) && routes.length > 0 ? `${routes.length} route(s)` : "No gateway routes found",
      });
    } catch {
      items.push({
        key: "routes",
        label: "Provider route configured",
        ok: false,
        detail: "Provider route check unavailable",
      });
    }

    try {
      const credentials = await backendFetch("/v1/provider-credentials");
      const active = Array.isArray(credentials)
        ? credentials.filter((item: { status?: string }) => item.status === "active")
        : [];
      items.push({
        key: "credentials",
        label: "Provider key configured",
        ok: active.length > 0,
        detail: active.length > 0 ? `${active.length} active provider key(s)` : "No active provider keys found",
      });
    } catch {
      items.push({
        key: "credentials",
        label: "Provider key configured",
        ok: false,
        detail: "Provider credential check unavailable",
      });
    }

    try {
      const policy = await backendFetch("/v1/policies/active");
      items.push({
        key: "policy",
        label: "Custom policy active",
        ok: Boolean(policy?.id),
        detail: policy?.id ? "Custom policy active" : "No active policy",
      });
    } catch {
      items.push({
        key: "policy",
        label: "Custom policy active",
        ok: false,
        detail: "Policy check unavailable",
      });
    }

    try {
      await backendFetch("/v1/audit-logs?limit=1");
      items.push({
        key: "audit",
        label: "Audit API reachable",
        ok: true,
        detail: "Audit endpoint responded",
      });
    } catch {
      items.push({
        key: "audit",
        label: "Audit API reachable",
        ok: false,
        detail: "Audit check unavailable",
      });
    }

    return NextResponse.json({
      ready: items.every((item) => item.ok),
      items,
    });
  } catch (error: unknown) {
    return handleApiError(error);
  }
}
