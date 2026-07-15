"use client";

export async function copyTextToClipboard(value: string): Promise<boolean> {
  if (!value) return false;

  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    // Fall through to the textarea fallback for plain HTTP deployments.
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  textarea.style.top = "0";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();

  try {
    return document.execCommand("copy");
  } finally {
    document.body.removeChild(textarea);
  }
}

export async function flashCopy<T>(
  value: string,
  setCopied: (value: T) => void,
  copiedValue: T,
  resetValue: T,
  timeout = 1500
): Promise<boolean> {
  const ok = await copyTextToClipboard(value);
  setCopied(copiedValue);
  window.setTimeout(() => setCopied(resetValue), timeout);
  return ok;
}
