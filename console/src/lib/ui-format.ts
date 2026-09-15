export function severityConfig(severity: string) {
  switch (severity) {
    case "critical":
      return { bg: "bg-red-500/15", text: "text-red-400", border: "border-red-500/30", dot: "bg-red-400" };
    case "high":
      return { bg: "bg-orange-500/15", text: "text-orange-400", border: "border-orange-500/30", dot: "bg-orange-400" };
    case "medium":
      return { bg: "bg-yellow-500/15", text: "text-yellow-400", border: "border-yellow-500/30", dot: "bg-yellow-400" };
    case "low":
      return { bg: "bg-blue-500/15", text: "text-blue-400", border: "border-blue-500/30", dot: "bg-blue-400" };
    default:
      return { bg: "bg-slate-500/15", text: "text-slate-400", border: "border-slate-500/30", dot: "bg-slate-400" };
  }
}

export function statusConfig(status: string) {
  switch (status) {
    case "OPEN":
      return { bg: "bg-red-500/15", text: "text-red-400", border: "border-red-500/30" };
    case "ACKNOWLEDGED":
    case "IN_PROGRESS":
      return { bg: "bg-blue-500/15", text: "text-blue-400", border: "border-blue-500/30" };
    case "AWAITING_APPROVAL":
      return { bg: "bg-yellow-500/15", text: "text-yellow-400", border: "border-yellow-500/30" };
    case "RESOLVED":
    case "FALSE_POSITIVE":
    case "ACCEPTED_RISK":
      return { bg: "bg-emerald-500/15", text: "text-emerald-400", border: "border-emerald-500/30" };
    default:
      return { bg: "bg-slate-500/15", text: "text-slate-400", border: "border-slate-500/30" };
  }
}

export function formatLabel(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

export function formatDateTime(iso: string) {
  try {
    const normalized = /(?:Z|[+-]\d{2}:?\d{2})$/.test(iso) ? iso : `${iso}Z`;
    return new Intl.DateTimeFormat("en-US", {
      timeZone: "Asia/Kolkata",
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(new Date(normalized));
  } catch {
    return iso;
  }
}

export function shortId(id: string) {
  return id.slice(0, 8) + "\u00e2\u20ac\u00a6";
}

export const readinessLabel = (value: string) => value.replaceAll("_", " ").toUpperCase();

// Human-view CSV: neutralize formula-like text before escaping; save/reopen behavior is spreadsheet-specific.
export function csvCell(value: unknown): string {
  let text = String(value ?? "");
  if (typeof value === "string" && (/^[\s\p{Cc}\p{Cf}]*[=+\-@＝＋－＠]/u.test(text) || /^[\t\r\n]/.test(text))) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}
