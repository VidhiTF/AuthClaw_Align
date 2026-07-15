import { NextResponse } from "next/server";
import { agentFetch, backendFetch, handleApiError } from "@/lib/api-client";

interface HealthItem {
  key: string;
  label: string;
  ok: boolean;
  detail: string;
}

export async function GET() {
  try {
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
          ? `${secretStatus.provider} provider, key ${secretStatus.key_version}: ${secretStatus.detail}`
          : `Backend returned ${backendRes.status}`,
      });
    } catch {
      items.push({
        key: "secret_management",
        label: "Secret management configured",
        ok: false,
        detail: `Could not reach ${backendUrl}/health`,
      });
    }

    try {
      const gatewayRes = await fetch(`${gatewayUrl}/health`, { cache: "no-store" });
      items.push({
        key: "gateway",
        label: "Gateway reachable",
        ok: gatewayRes.ok,
        detail: gatewayRes.ok ? gatewayUrl : `Gateway returned ${gatewayRes.status}`,
      });
    } catch {
      items.push({
        key: "gateway",
        label: "Gateway reachable",
        ok: false,
        detail: `Could not reach ${gatewayUrl}`,
      });
    }

    try {
      const sessions = await agentFetch("/chat/sessions");
      items.push({
        key: "agent",
        label: "Agent service authenticated",
        ok: Array.isArray(sessions),
        detail: Array.isArray(sessions) ? "Control-plane identity accepted" : "Unexpected agent response",
      });
    } catch (error: unknown) {
      items.push({
        key: "agent",
        label: "Agent service authenticated",
        ok: false,
        detail: error instanceof Error ? error.message : "Failed to reach agent service",
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
    } catch (error: unknown) {
      items.push({
        key: "routes",
        label: "Provider route configured",
        ok: false,
        detail: error instanceof Error ? error.message : "Failed to check routes",
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
    } catch (error: unknown) {
      items.push({
        key: "credentials",
        label: "Provider key configured",
        ok: false,
        detail: error instanceof Error ? error.message : "Failed to check credentials",
      });
    }

    try {
      const policy = await backendFetch("/v1/policies/active");
      items.push({
        key: "policy",
        label: "Custom policy active",
        ok: Boolean(policy?.id),
        detail: policy?.name ? `${policy.name} v${policy.version}` : "No active policy",
      });
    } catch (error: unknown) {
      items.push({
        key: "policy",
        label: "Custom policy active",
        ok: false,
        detail: error instanceof Error ? error.message : "No active policy",
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
    } catch (error: unknown) {
      items.push({
        key: "audit",
        label: "Audit API reachable",
        ok: false,
        detail: error instanceof Error ? error.message : "Failed to check audit endpoint",
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
