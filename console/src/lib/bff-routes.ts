export type BffMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
export type BffBody = "none" | "json" | "optional-json";

const ALLOWED: Record<BffMethod, RegExp> = {
  GET: /^(users(?:\/invites|\/me\/security)?|usage-limits|tenants\/current|red-team|provider-credentials|notifications|gateways|evidence(?:\/[^/]+)?|findings(?:\/summary\/dashboard|\/[^/]+)?|ephemeral-workers\/(?:tokens|connectors)|compliance-scores(?:\/history|\/[^/]+)?|api-keys|approvals|access-requests)$/,
  POST: /^(users|users\/invite|users\/me\/mfa\/(?:setup|confirm|disable|recovery-codes)|users\/[^/]+\/mfa\/reset|tenants|red-team|provider-credentials|provider-credentials\/[^/]+\/rotate|policies\/(?:validate|simulate|rollback)|policies\/[^/]+\/activate|notifications\/(?:read-all|[^/]+\/read)|gateways|ephemeral-workers\/tokens(?:\/[^/]+\/revoke)?|api-keys|api-keys\/[^/]+\/rotate|data-subject-requests(?:\/[^/]+\/(?:verify|approve|export|delete))?|workflows\/[^/]+\/(?:approve|reject|remediate)|approvals\/[^/]+\/(?:approve|reject))$/,
  PUT: /^gateways\/[^/]+$/,
  PATCH: /^(tenants\/current\/status|findings\/[^/]+\/status|access-requests\/[^/]+\/status)$/,
  DELETE: /^(users\/(?:invites\/[^/]+|(?!me$|invite$|invites$)[^/]+)|provider-credentials\/[^/]+|gateways\/[^/]+|api-keys\/[^/]+)$/,
};

const NO_BODY_POST = /^(users\/me\/mfa\/setup|notifications\/(?:read-all|[^/]+\/read)|policies\/[^/]+\/activate|ephemeral-workers\/tokens\/[^/]+\/revoke|workflows\/[^/]+\/(?:reject|remediate)|approvals\/[^/]+\/reject)$/;
const OPTIONAL_BODY_POST = /^(workflows|approvals)\/[^/]+\/approve$/;
const CREATED = /^(users|tenants|provider-credentials|red-team|gateways|ephemeral-workers\/tokens|api-keys(?:\/[^/]+\/rotate)?)$/;

export function resolveBffRoute(method: BffMethod, path: string) {
  if (!ALLOWED[method].test(path)) return null;

  let backendPath = `/v1/${path}`;
  if (path === "approvals" || path.startsWith("approvals/")) {
    backendPath = `/v1/workflows/${path}`;
  } else if (path === "access-requests" || path.startsWith("access-requests/")) {
    backendPath = `/api/public/v1/${path}`;
  } else if (method === "POST" && path === "red-team") {
    backendPath = "/v1/red-team/runs";
  } else if (path === "compliance-scores/history") {
    backendPath = "/v1/compliance-scores/history/trend";
  }

  const body: BffBody = method !== "POST"
    ? (method === "PUT" || method === "PATCH" ? "json" : "none")
    : OPTIONAL_BODY_POST.test(path)
      ? "optional-json"
      : NO_BODY_POST.test(path)
        ? "none"
        : "json";
  const status = method === "DELETE" ? 204 : path === "users/invite" ? 202 : CREATED.test(path) && method === "POST" ? 201 : undefined;
  return { backendPath, body, status };
}
