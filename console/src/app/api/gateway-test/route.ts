import { NextResponse } from "next/server";
import { getSessionContext } from "@/lib/api-client";
import { isProvider, providerCatalog, type Provider } from "@/lib/providers";

interface ProviderCredential {
  provider: string;
  status: string;
}

interface ValidationCheck {
  label: string;
  ok: boolean;
  detail: string;
}

const GATEWAY_URL =
  process.env.GATEWAY_INTERNAL_URL ||
  process.env.NEXT_PUBLIC_GATEWAY_URL ||
  "http://localhost:8080";

const BACKEND_URL = process.env.API_URL || "http://localhost:8000";

function trimBody(value: string) {
  return value.length > 1200 ? `${value.slice(0, 1200)}...` : value;
}

function parsedMessage(parsed: unknown) {
  if (!parsed || typeof parsed !== "object" || !("message" in parsed)) return "";
  const message = (parsed as { message?: unknown }).message;
  return typeof message === "string" ? message : "";
}

function validationChecks(status: number, contentType: string, parsed: unknown): ValidationCheck[] {
  const message = parsedMessage(parsed);
  const policyUnavailable = message.toLowerCase().includes("policy evaluation engine unavailable");

  return [
    { label: "Provider credential", ok: true, detail: "Active encrypted upstream key found" },
    { label: "Gateway route", ok: status > 0, detail: `HTTP ${status}` },
    {
      label: "Policy engine",
      ok: !policyUnavailable,
      detail: policyUnavailable ? "OPA/policy engine unavailable; start OPA or check OPA_URL" : "No policy-engine availability error returned",
    },
    { label: "Response parse", ok: parsed !== null, detail: parsed === null ? "Non-JSON response body" : "JSON response parsed" },
    {
      label: "Content type",
      ok: contentType.includes("application/json") || contentType.includes("text/event-stream") || contentType === "",
      detail: contentType || "No content-type header returned",
    },
  ];
}

async function hasActiveProviderCredential(apiKey: string, provider: Provider) {
  const response = await fetch(`${BACKEND_URL}/v1/provider-credentials`, {
    headers: {
      Authorization: `Bearer ${apiKey}`,
    },
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error("Could not check provider key vault");
  }
  const credentials = (await response.json()) as ProviderCredential[];
  return credentials.some((credential) => credential.provider === provider && credential.status === "active");
}

export async function POST(request: Request) {
  try {
    const context = await getSessionContext();
    if ("response" in context) return context.response;
    const session = context.session!;

    const body = await request.json().catch(() => ({}));
    const requestedProvider = String(body.provider || "gemini");
    if (!isProvider(requestedProvider)) {
      return NextResponse.json({ error: "Unsupported provider" }, { status: 400 });
    }
    const provider: Provider = requestedProvider;
    const test = providerCatalog[provider];

    const hasProviderKey = await hasActiveProviderCredential(session.apiKey, provider);
    if (!hasProviderKey) {
      return NextResponse.json(
        {
          error: "ProviderCredentialMissing",
          message: `Save an active ${test.shortLabel} provider API key before running a live gateway test.`,
          provider,
        },
        { status: 409 },
      );
    }

    const requestId = `connect-test-${Date.now()}`;
    const startedAt = Date.now();
    const gatewayResponse = await fetch(`${GATEWAY_URL}${test.path}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.apiKey}`,
        "X-Provider": provider,
        "X-Request-ID": requestId,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(test.testBody),
      cache: "no-store",
    });
    const responseText = await gatewayResponse.text();
    const durationMs = Date.now() - startedAt;
    const contentType = gatewayResponse.headers.get("content-type") || "";

    let parsed: unknown = null;
    try {
      parsed = responseText ? JSON.parse(responseText) : null;
    } catch {
      parsed = null;
    }

    return NextResponse.json({
      ok: gatewayResponse.ok,
      status: gatewayResponse.status,
      provider,
      request_id: requestId,
      duration_ms: durationMs,
      path: test.path,
      gateway_url: GATEWAY_URL,
      content_type: contentType,
      error: !gatewayResponse.ok ? parsedMessage(parsed) || `Gateway returned ${gatewayResponse.status}` : undefined,
      contract: {
        readiness: test.readiness,
        last_reviewed: test.lastReviewed,
        payload: test.payloadContract,
        streaming: test.streamingContract,
        ci_gate: test.ciGate,
      },
      checks: validationChecks(gatewayResponse.status, contentType, parsed),
      response: parsed,
      raw: parsed ? undefined : trimBody(responseText),
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Gateway test failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
