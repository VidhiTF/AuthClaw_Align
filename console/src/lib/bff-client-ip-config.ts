export function validateBffClientIPConfig() {
  const enabled = process.env.AUTHCLAW_BFF_CLIENT_IP_ENABLED ?? "false";
  if (enabled !== "true" && enabled !== "false") {
    throw new Error("AUTHCLAW_BFF_CLIENT_IP_ENABLED must be true or false");
  }
  if (enabled === "true" && (
    process.env.AUTHCLAW_CONSOLE_ALB_INGRESS_ONLY !== "true" ||
    (process.env.BFF_CLIENT_IP_SECRET?.length ?? 0) < 32
  )) {
    throw new Error("BFF client identity requires ALB-only ingress and a managed secret");
  }
}
