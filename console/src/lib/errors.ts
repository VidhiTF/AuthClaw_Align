type ApiErrorCandidate = {
  detail?: unknown;
  message?: unknown;
  error?: unknown;
};

type ValidationErrorItem = {
  path?: unknown;
  message?: unknown;
  msg?: unknown;
};

export function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object");
}

export function apiErrorMessage(data: unknown, fallback: string): string {
  if (!isRecord(data)) return fallback;
  const payload = data as ApiErrorCandidate;
  const candidate = payload.detail ?? payload.message ?? payload.error;
  if (typeof candidate === "string") return candidate;
  if (isRecord(candidate)) {
    if (typeof candidate.message === "string") {
      const errors = Array.isArray(candidate.errors)
        ? candidate.errors
            .map((item: ValidationErrorItem) => {
              const path = typeof item.path === "string" ? item.path : "policy";
              const message = typeof item.message === "string" ? item.message : "";
              return message ? `${path}: ${message}` : "";
            })
            .filter(Boolean)
        : [];
      return errors.length ? `${candidate.message}: ${errors.join("; ")}` : candidate.message;
    }
  }
  if (Array.isArray(candidate)) {
    const messages = candidate
      .map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object" && "msg" in item) return String(item.msg);
        return "";
      })
      .filter(Boolean);
    if (messages.length) return messages.join(" ");
  }
  return fallback;
}

export function getErrorMessage(error: unknown, fallback = "Request failed"): string {
  return error instanceof Error ? error.message : fallback;
}

export function getErrorStatus(error: unknown, fallback = 500): number {
  return isRecord(error) && typeof error.status === "number" ? error.status : fallback;
}
