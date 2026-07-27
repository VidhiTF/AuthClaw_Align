import { createHmac } from "crypto";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { apiErrorMessage, getErrorMessage, getErrorStatus } from "./errors";
import { sessionStore } from "./session-store";

const BACKEND_URL = process.env.API_URL || "http://localhost:8000";
const AGENT_URL = process.env.AGENT_INTERNAL_URL || "http://localhost:8001";
const BACKEND_TIMEOUT_MS = 15000;
const AGENT_TIMEOUT_MS = Number(process.env.AGENT_TIMEOUT_MS || "45000");

class BackendRequestError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "BackendRequestError";
    this.status = status;
  }
}

export { apiErrorMessage, getErrorMessage, getErrorStatus };

interface RequestOptions extends RequestInit {
  params?: Record<string, string>;
}

interface AgentRequestOptions extends RequestInit {
  forwardGatewayKey?: boolean;
}

type ErrorKey = "detail" | "error";
type JsonBodyMapper = (body: Record<string, unknown>) => unknown;

export type RouteContext<T extends Record<string, string> = { id: string }> = {
  params: Promise<T>;
};

async function readSessionContext(invalidSessionMessage?: string) {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get("authclaw_session")?.value;
  if (!sessionToken) return null;
  let payload;
  try {
    payload = JSON.parse(sessionToken);
  } catch (error) {
    if (invalidSessionMessage) throw new Error(invalidSessionMessage);
    throw error;
  }
  return { payload, session: sessionStore.getSession(payload.sessionId) };
}

async function fetchBackend(url: string, options: RequestInit) {
  try {
    return await fetch(url, {
      ...options,
      signal: options.signal || AbortSignal.timeout(BACKEND_TIMEOUT_MS),
    });
  } catch (error: unknown) {
    if (error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError")) {
      throw new BackendRequestError("Backend request timed out", 504);
    }
    throw error;
  }
}

export async function getSessionContext() {
  const context = await readSessionContext("Unauthorized: Invalid session format");
  if (!context) return { response: NextResponse.json({ error: "Unauthorized" }, { status: 401 }) };
  if (!context.session) {
    const response = NextResponse.json({ error: "Unauthorized: Session expired or invalid" }, { status: 401 });
    response.cookies.delete("authclaw_session");
    return { response };
  }
  return context;
}

export async function backendFetch(path: string, options: RequestOptions = {}) {
  const context = await readSessionContext();
  if (!context) throw new Error("Unauthorized: No session cookie found");
  if (!context.session) throw new Error("Unauthorized: Session expired or invalid");

  let url = `${BACKEND_URL}${path}`;
  if (options.params) {
    const searchParams = new URLSearchParams(options.params);
    url += `?${searchParams.toString()}`;
  }

  const headers = new Headers(options.headers);
  headers.set("Authorization", `Bearer ${context.session.apiKey}`);
  headers.set("Content-Type", "application/json");

  const response = await fetchBackend(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorDetail = "Backend request failed";
    try {
      const errorJson = await response.json();
      errorDetail = apiErrorMessage(errorJson, errorDetail);
    } catch {
      // ignore JSON parse error
    }
    throw new BackendRequestError(errorDetail, response.status);
  }

  if (response.status === 204) {
    return null;
  }

  return response.json();
}

export async function agentFetch(path: string, options: AgentRequestOptions = {}) {
  const context = await readSessionContext();
  if (!context) throw new BackendRequestError("Unauthorized: No session cookie found", 401);
  if (!context.session) throw new BackendRequestError("Unauthorized: Session expired or invalid", 401);

  const validation = await fetchBackend(`${BACKEND_URL}/v1/auth/me`, {
    headers: { Authorization: `Bearer ${context.session.apiKey}` },
  });
  if (!validation.ok) {
    if (validation.status === 401 || validation.status === 403) {
      sessionStore.deleteSession(context.session.sessionId);
      throw new BackendRequestError("Unauthorized: Session expired or invalid", 401);
    }
    throw new BackendRequestError("Backend request failed", validation.status);
  }

  const secret = process.env.AUTHCLAW_INTERNAL_SERVICE_SECRET;
  if (!secret) throw new BackendRequestError("Agent service authentication is not configured", 503);

  const method = (options.method || "GET").toUpperCase();
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const principal = context.session;
  const signaturePayload = [
    timestamp,
    method,
    path,
    principal.tenantId,
    principal.userId,
    principal.role.toLowerCase(),
  ].join("\n");
  const headers = new Headers(options.headers);
  headers.set("X-AuthClaw-Timestamp", timestamp);
  headers.set("X-AuthClaw-Tenant-ID", principal.tenantId);
  headers.set("X-AuthClaw-User-ID", principal.userId);
  headers.set("X-AuthClaw-Role", principal.role.toLowerCase());
  headers.set("X-AuthClaw-Signature", createHmac("sha256", secret).update(signaturePayload).digest("hex"));
  if (options.forwardGatewayKey) headers.set("X-API-Key", principal.apiKey);
  if (options.body !== undefined) headers.set("Content-Type", "application/json");

  const fetchOptions = { ...options };
  delete fetchOptions.forwardGatewayKey;

  const response = await fetch(`${AGENT_URL}${path}`, {
    ...fetchOptions,
    method,
    headers,
    signal: options.signal || AbortSignal.timeout(AGENT_TIMEOUT_MS),
    cache: "no-store",
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new BackendRequestError(apiErrorMessage(body, "Agent request failed"), response.status);
  }
  if (response.status === 204) return null;
  return response.json();
}

export async function routeParam<T extends Record<string, string>>(
  context: RouteContext<T>,
  key: keyof T
) {
  const params = await context.params;
  return params[key];
}

export async function proxyBackend(path: string, options: RequestOptions = {}, status?: number) {
  try {
    const data = await backendFetch(path, options);
    if (status === 204) return new Response(null, { status: 204 });
    return NextResponse.json(data, status ? { status } : undefined);
  } catch (error: unknown) {
    return handleApiError(error);
  }
}

export async function proxyBackendJson(
  request: Request,
  path: string,
  method: string,
  status?: number
) {
  try {
    const body = await request.json();
    return proxyBackend(path, {
      method,
      body: JSON.stringify(body),
    }, status);
  } catch (error: unknown) {
    return handleApiError(error);
  }
}

export async function proxyBackendOptionalJson(
  request: Request,
  path: string,
  method: string,
  status?: number
) {
  let body = {};
  try {
    body = await request.json();
  } catch {
    // Preserve routes that treated an empty or invalid body as an empty object.
  }
  return proxyBackend(path, {
    method,
    body: JSON.stringify(body),
  }, status);
}

export async function publicBackendJson(
  path: string,
  options: RequestInit,
  fallback: string,
  errorKey: ErrorKey = "error",
  tolerantJson = false
) {
  try {
    const response = await fetchBackend(`${BACKEND_URL}${path}`, options);
    const data = tolerantJson ? await response.json().catch(() => ({})) : await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch (error: unknown) {
    return NextResponse.json({ [errorKey]: getErrorMessage(error, fallback) }, { status: 500 });
  }
}

export async function publicBackendPostJson(
  request: Request,
  path: string,
  fallback: string,
  errorKey: ErrorKey = "detail",
  mapBody: JsonBodyMapper = (body) => body,
  options: RequestInit = {},
  tolerantJson = false
) {
  try {
    const body = await request.json();
    const headers = new Headers(options.headers);
    headers.set("Content-Type", "application/json");
    return publicBackendJson(
      path,
      {
        ...options,
        method: "POST",
        headers,
        body: JSON.stringify(mapBody(body)),
      },
      fallback,
      errorKey,
      tolerantJson
    );
  } catch (error: unknown) {
    return NextResponse.json({ [errorKey]: getErrorMessage(error, fallback) }, { status: 500 });
  }
}

export async function proxyBackendWithSessionCheck(path: string, options: RequestOptions = {}) {
  try {
    const context = await readSessionContext();
    if (!context) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!context.session) {
      return NextResponse.json({ error: "Session expired" }, { status: 401 });
    }
    const data = await backendFetch(path, options);
    return NextResponse.json(data);
  } catch (error: unknown) {
    return handleApiError(error);
  }
}

export function handleApiError(error: unknown) {
  const message = getErrorMessage(error);
  const isUnauthorized = message.includes("Unauthorized");
  const status = getErrorStatus(error, isUnauthorized ? 401 : 500);
  const response = NextResponse.json({ error: message }, { status });
  if (isUnauthorized) {
    response.cookies.delete("authclaw_session");
  }
  return response;
}
