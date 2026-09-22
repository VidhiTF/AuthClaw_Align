import { bodySha256, controlPlaneHeaders } from "./control-plane-auth";
import { cookies } from "next/headers";
import { sessionCookieName } from "@/lib/cookie-options";
import { NextResponse } from "next/server";
import { apiErrorMessage, getErrorMessage, getErrorStatus } from "./errors";

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
  const token = cookieStore.get(sessionCookieName())?.value;
  if (!token || !token.startsWith("acl_session_")) return null;
  const validation = await fetchBackend(`${BACKEND_URL}/v1/auth/me`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (validation.status >= 500) throw new BackendRequestError("Identity service unavailable", 503);
  if (!validation.ok) {
    if (invalidSessionMessage) throw new Error(invalidSessionMessage);
    return { payload: null, session: null };
  }
  const principal = await validation.json();
  const session = {
    sessionId: token,
    apiKey: token,
    userId: principal.id as string,
    tenantId: principal.tenant_id as string,
    scopes: Array.isArray(principal.scopes) ? principal.scopes as string[] : [],
    role: principal.role as string,
    expiresAt: 0,
  };
  return { payload: principal, session };
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
    response.cookies.delete(sessionCookieName());
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
      if (response.status < 500) errorDetail = apiErrorMessage(errorJson, errorDetail);
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

  const method = (options.method || "GET").toUpperCase();
  const principal = context.session;
  const url = new URL(`${AGENT_URL}${path}`);
  if (!path.startsWith("/") || url.origin !== new URL(AGENT_URL).origin || url.hash
      || (options.body != null && typeof options.body !== "string")) {
    throw new BackendRequestError("Unsupported signed request", 400);
  }
  const headers = new Headers(options.headers);
  let requestBody = (options.body ?? "") as string;
  let mfaAssertion: {
    verified_at: number;
    operation: string;
    body_sha256: string;
    assertion_id: string;
    role: string;
  } | undefined;
  if (method === "POST" && /^\/(?:approve|execute)\/[A-Za-z0-9._:-]+$/.test(url.pathname)) {
    let privilegedBody: Record<string, unknown>;
    try {
      privilegedBody = JSON.parse(requestBody || "{}");
    } catch {
      throw new BackendRequestError("Invalid privileged agent request", 400);
    }
    const code = privilegedBody.mfa_code;
    if (typeof code !== "string" || code.length < 6 || code.length > 64) {
      throw new BackendRequestError("MFA code is required", 401);
    }
    delete privilegedBody.mfa_code;
    requestBody = JSON.stringify(privilegedBody);
    const assertionResponse = await fetchBackend(`${BACKEND_URL}/v1/auth/mfa/agent-assertion`, {
      method: "POST",
      headers: { Authorization: `Bearer ${context.session.apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        method,
        path: url.pathname,
        body_sha256: bodySha256(requestBody),
      }),
      cache: "no-store",
    });
    if (!assertionResponse.ok) {
      const body = await assertionResponse.json().catch(() => ({}));
      throw new BackendRequestError(apiErrorMessage(body, "MFA verification failed"), assertionResponse.status);
    }
    mfaAssertion = await assertionResponse.json();
    if (!mfaAssertion || !["owner", "admin"].includes(mfaAssertion.role)) {
      throw new BackendRequestError("Invalid MFA assertion role", 403);
    }
    principal.role = mfaAssertion.role;
  }
  if (options.forwardGatewayKey) headers.set("X-API-Key", principal.apiKey);
  if (requestBody !== "") headers.set("Content-Type", "application/json");
  try {
    for (const [name, value] of Object.entries(controlPlaneHeaders(
      url, method, requestBody, headers.get("Content-Type") || "", principal, mfaAssertion,
    ))) {
      headers.set(name, value);
    }
  } catch {
    throw new BackendRequestError("Agent service authentication is not configured", 503);
  }

  const fetchOptions = { ...options };
  delete fetchOptions.forwardGatewayKey;
  fetchOptions.body = requestBody || undefined;

  const response = await fetch(url.toString(), {
    ...fetchOptions,
    method,
    headers,
    signal: options.signal || AbortSignal.timeout(AGENT_TIMEOUT_MS),
    cache: "no-store",
    redirect: "error",
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
  tolerantJson = false,
  request?: Request
) {
  try {
    if (request && (path === "/v1/auth/password-reset/request" || /^\/v1\/trust-center\/public\/[^/]+\/(request|verify)-access$/.test(path))) {
      if (options.body != null && typeof options.body !== "string") throw new Error("Signed request body must be text");
      const { bffClientIPHeaders } = await import("./bff-client-ip");
      const headers = new Headers(options.headers);
      for (const [key, value] of Object.entries(bffClientIPHeaders(request, options.body ?? "", path))) headers.set(key, value);
      options = { ...options, headers };
    }
    const response = await fetchBackend(`${BACKEND_URL}${path}`, options);
    const data = tolerantJson ? await response.json().catch(() => ({})) : await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch {
    return NextResponse.json({ [errorKey]: fallback }, { status: 500 });
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
    const payload = JSON.stringify(mapBody(body));
    return publicBackendJson(
      path,
      {
        ...options,
        method: "POST",
        headers,
        body: payload,
      },
      fallback,
      errorKey,
      tolerantJson,
      request
    );
  } catch {
    return NextResponse.json({ [errorKey]: fallback }, { status: 500 });
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
  const response = NextResponse.json({ error: status >= 500 ? "Request failed" : message }, { status });
  if (isUnauthorized) {
    response.cookies.delete(sessionCookieName());
  }
  return response;
}
