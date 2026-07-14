/* eslint-disable @typescript-eslint/no-explicit-any -- compatibility facade preserves imported Axios call-site inference */
import { clearTokens, getTokens } from './auth';
import { mapCanonicalRequest, normalizeCanonicalResponse } from './api-contract';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

type RequestConfig = {
  params?: Record<string, unknown>;
  responseType?: 'blob' | 'json' | 'text';
  headers?: Record<string, string>;
};

export type ApiResponse<T = unknown> = {
  data: T;
  status: number;
  headers: Headers;
};

export class ApiRequestError extends Error {
  response: { status: number; data: unknown };

  constructor(status: number, data: unknown) {
    const detail =
      typeof data === 'object' && data && 'detail' in data
        ? String((data as { detail: unknown }).detail)
        : `Request failed with status ${status}`;
    super(detail);
    this.name = 'ApiRequestError';
    this.response = { status, data };
  }
}

function appendQuery(url: URL, params?: Record<string, unknown>) {
  if (!params) return;
  for (const [key, rawValue] of Object.entries(params)) {
    if (rawValue === null || rawValue === undefined) continue;
    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    for (const value of values) {
      if (value !== null && value !== undefined) {
        url.searchParams.append(key, String(value));
      }
    }
  }
}

async function parseResponse(response: Response, responseType?: RequestConfig['responseType']) {
  if (response.status === 204) return null;
  if (responseType === 'blob') return response.blob();
  if (responseType === 'text') return response.text();
  const text = await response.text();
  if (!text) return null;
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('json')) {
    try {
      return JSON.parse(text);
    } catch {
      return { detail: 'The server returned invalid JSON.' };
    }
  }
  return text;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  config: RequestConfig = {},
): Promise<ApiResponse<T>> {
  const mapped = mapCanonicalRequest(method, path);
  const url = new URL(mapped.path.replace(/^\/+/, ''), `${API_URL.replace(/\/$/, '')}/`);
  appendQuery(url, config.params);

  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...config.headers,
  };
  const tokens = getTokens();
  if (tokens?.accessToken) headers.Authorization = `Bearer ${tokens.accessToken}`;

  const init: RequestInit = { method: mapped.method, headers };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const response = await fetch(url, init);
  const parsed = await parseResponse(response, config.responseType);
  const data = config.responseType === 'blob'
    ? parsed
    : normalizeCanonicalResponse(path, parsed);
  if (!response.ok) {
    if (response.status === 401) {
      clearTokens();
      if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
        window.location.href = '/login';
      }
    }
    throw new ApiRequestError(response.status, data);
  }
  return { data: data as T, status: response.status, headers: response.headers };
}

export const apiClient = {
  get<T = any>(path: string, config?: RequestConfig) {
    return request<T>('GET', path, undefined, config);
  },
  post<T = any>(path: string, body?: unknown, config?: RequestConfig) {
    return request<T>('POST', path, body, config);
  },
  put<T = any>(path: string, body?: unknown, config?: RequestConfig) {
    return request<T>('PUT', path, body, config);
  },
  patch<T = any>(path: string, body?: unknown, config?: RequestConfig) {
    return request<T>('PATCH', path, body, config);
  },
  delete<T = any>(path: string, config?: RequestConfig) {
    return request<T>('DELETE', path, undefined, config);
  },
};
