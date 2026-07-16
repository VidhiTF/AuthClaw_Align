"use client";

import { apiErrorMessage } from "./errors";

type FetchJsonOptions = RequestInit & {
  fallback?: string;
  preferApiError?: boolean;
  redirectUnauthorized?: boolean;
};

export function jsonRequest(method: "POST" | "PATCH" | "PUT" | "DELETE", body?: unknown): RequestInit {
  return {
    method,
    headers: { "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  };
}

export async function responseJson<T>(res: Response): Promise<T> {
  return res.json() as Promise<T>;
}

export async function responseJsonOr<T>(res: Response, fallback: T): Promise<T> {
  return res.json().catch(() => fallback) as Promise<T>;
}

export async function fetchJson<T>(input: RequestInfo | URL, options: FetchJsonOptions = {}): Promise<T | null> {
  const { fallback = "Request failed", preferApiError = true, redirectUnauthorized = true, ...init } = options;
  const res = await fetch(input, init);
  if (redirectUnauthorized && res.status === 401) {
    window.location.href = "/login";
    return null;
  }
  if (!res.ok) {
    if (!preferApiError) throw new Error(fallback);
    const data = await res.json().catch(() => ({}));
    throw new Error(apiErrorMessage(data, fallback));
  }
  return res.json() as Promise<T>;
}

export function toggleValue<T>(values: T[], value: T): T[] {
  return values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
}
