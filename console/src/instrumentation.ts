import { validateBffClientIPConfig } from "./lib/bff-client-ip-config.ts";

export function register() {
  validateBffClientIPConfig();
  if (
    process.env.AUTHCLAW_ENV === "production" &&
    process.env.AUTHCLAW_COOKIE_SECURE !== "true"
  ) {
    throw new Error("AUTHCLAW_COOKIE_SECURE must be true in production");
  }
}
