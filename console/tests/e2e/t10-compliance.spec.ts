import { expect, test } from "@playwright/test";

// Scoring responses are intercepted; this verifies rendering, not backend qualification.
// E2E_T10_AUTH_FIXTURE permits an isolated auth fixture instead of the normal test login.
const generatedAt = "2026-09-18T06:00:00Z";
const version = "evidence-v2";
const control = {
  id: "CC6.1", name: "Logical access", description: "Access review", weight: 1,
  score: 0, status: "non_compliant", evidence: [], gaps: ["Assessment expired; review required"],
  activity_diagnostics: { score: 100, evidence: ["10000 audit events"], gaps: [], authoritative: false },
  evidence_assessment: {
    state: "blocked", reason_codes: ["stale_assessment"], required_count: 1,
    qualified_count: 0, as_of: generatedAt, valid_until: null,
  },
};
const scoreResponse = {
  overall_score: 0, readiness_level: "insufficient_evidence", calculation_version: version, generated_at: generatedAt,
  frameworks: ["SOC2", "GDPR", "HIPAA"].map((framework) => ({
    framework, score: 0, readiness_level: "insufficient_evidence", calculation_version: version,
    generated_at: generatedAt, controls: [control], metrics: { evidence_count: 10000, audit_event_count: 10000, open_findings: 0 },
  })),
  trust_summary: {
    generated_at: generatedAt, calculation_version: version,
    counts: { verified: 0, in_progress: 0, planned: 1 },
    verified: [], in_progress: [], planned: [{ ...control, framework: "SOC2" }],
  },
};

test.beforeEach(async ({ context, page, baseURL }) => {
  if (process.env.E2E_T10_AUTH_FIXTURE === "true") {
    await context.addCookies([{ name: "authclaw_session", value: "acl_session_t10_fixture", url: baseURL! }]);
  } else {
    await page.goto("/login");
    await page.locator('input[type="email"]').fill(process.env.E2E_LOGIN_EMAIL || "admin@authclaw-lite.demo");
    await page.locator('input[type="password"]').fill(process.env.E2E_LOGIN_PASSWORD || "AuthClawDemo!234");
    await page.getByPlaceholder("Only needed if your email has multiple tenants").fill(process.env.E2E_LOGIN_TENANT || "AuthClaw Lite Demo");
    await page.getByRole("button", { name: "Sign In" }).click();
    await page.waitForURL("/connect");
  }
  await page.route("**/api/**", (route) => {
    const pathname = new URL(route.request().url()).pathname;
    const body = pathname === "/api/auth/session" ? { role: "viewer" }
      : pathname === "/api/dashboard" ? { totalRequests: 10000, redactions24h: 10, openApprovals: 0, recentActivity: [] }
      : { items: [], unread_count: 0 };
    return route.fulfill({ json: body });
  });
});

test("compliance exposes blocked evidence, legacy history, and method boundaries", async ({ page }) => {
  await page.route("**/api/compliance-scores?*", (route) => route.fulfill({ json: scoreResponse }));
  await page.route("**/api/compliance-scores/history?*", (route) => route.fulfill({ json: { items: [
    { framework: "SOC2", snapshot_date: "2026-09-18", overall_score: 0, calculation_version: version },
    { framework: "SOC2", snapshot_date: "2026-09-18", overall_score: 100 },
  ] } }));
  await page.goto("/compliance");
  await expect(page.getByText("SOC2 Control Assessments")).toBeVisible();
  await expect(page.getByText("Evidence blocked: 0/1 requirements qualified").first()).toBeVisible();
  await expect(page.getByText("Assessment expired; review required").first()).toBeVisible();
  await expect(page.getByText("Calculation version: legacy_unversioned")).toBeVisible();
  await expect(page.getByText("Calculation method changed. Scores across this boundary are not comparable.")).toBeVisible();
  await expect(page.getByText("Activity diagnostic score: 100% (not readiness)")).toBeVisible();
  await expect(page.getByText("NON COMPLIANT - 0%", { exact: true })).toHaveClass(/text-red-300/);
  await expect(page.getByText("Not qualified", { exact: true })).toBeVisible();
  await expect(page.getByText("INSUFFICIENT EVIDENCE", { exact: true })).toHaveCount(3);
  await expect(page.getByText("MONITOR", { exact: true })).toHaveCount(0);
  await expect(page.getByText("AUDIT READY", { exact: true })).toHaveCount(0);
});

test("failed score refresh removes prior assessment and Trust Summary", async ({ page }) => {
  let fail = false;
  await page.route("**/api/compliance-scores?*", (route) => route.fulfill(
    fail ? { status: 503, json: { detail: "unavailable" } } : { json: scoreResponse },
  ));
  await page.goto("/compliance");
  await expect(page.getByText("Evidence blocked: 0/1 requirements qualified").first()).toBeVisible();
  fail = true;
  await page.getByRole("button", { name: "Refresh framework statistics" }).click();
  await expect(page.getByText("Current compliance assessment unavailable. Refresh to try again.")).toBeVisible();
  await expect(page.getByText("Evidence blocked: 0/1 requirements qualified")).toHaveCount(0);
  await expect(page.getByText("Trust Summary is unavailable for this response.")).toBeVisible();
  await expect(page.getByText("0%", { exact: true })).toHaveCount(0);
});

test("history failure cannot silently preserve previous snapshots", async ({ page }) => {
  await page.route("**/api/compliance-scores?*", (route) => route.fulfill({ json: scoreResponse }));
  await page.route("**/api/compliance-scores/history?*", (route) => route.fulfill({ status: 503, json: {} }));
  await page.goto("/compliance");
  await expect(page.getByText("Failed to load score history; refresh to retrieve a complete view")).toBeVisible();
  await expect(page.getByText("0%", { exact: true })).toHaveCount(0);
});

test("mixed calculation versions fail closed without rendering scores", async ({ page }) => {
  await page.route("**/api/compliance-scores?*", (route) => route.fulfill({ json: {
    ...scoreResponse, calculation_version: "different-method",
  } }));
  await page.goto("/compliance");
  await expect(page.getByText("Compliance snapshot mismatch")).toBeVisible();
  await expect(page.getByText("0%", { exact: true })).toHaveCount(0);
});

test("overview shows server readiness and clears it when the next request fails", async ({ page }) => {
  let fail = false;
  await page.route("**/api/compliance-scores?*", (route) => route.fulfill(
    fail ? { status: 503, json: {} } : { json: scoreResponse },
  ));
  await page.goto("/overview");
  await expect(page.getByRole("cell", { name: "INSUFFICIENT EVIDENCE", exact: true })).toHaveCount(3);
  await expect(page.getByRole("cell", { name: "MONITOR", exact: true })).toHaveCount(0);
  await expect(page.getByText(/Calculation version: evidence-v2/)).toBeVisible();
  fail = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Current compliance assessment unavailable" })).toHaveText("Current compliance assessment unavailable. Refresh to try again.");
  await expect(page.getByRole("cell", { name: "INSUFFICIENT EVIDENCE", exact: true })).toHaveCount(0);
});
