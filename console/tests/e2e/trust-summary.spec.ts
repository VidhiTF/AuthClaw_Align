import { expect, test } from "@playwright/test";

const trustCenterAccess = "verified-test-access";

test.beforeEach(async ({ page }) => {
  await page.addInitScript((access) => {
    sessionStorage.setItem("trust-center:demo-token", access);
  }, trustCenterAccess);
});

const packageResponse = (trustSummary?: Record<string, unknown>) => ({
  tenant: { id: "tenant-one", name: "Example Tenant", tier: "enterprise" },
  share: {
    label: "Readiness review",
    auditor_email: "",
    frameworks: ["SOC2"],
    expires_at: "2026-12-31T00:00:00Z",
    status: "active",
    access_count: 0,
  },
  scores: {
    overall_score: 90,
    readiness_level: "audit_ready",
    frameworks: [{
      framework: "SOC2",
      score: 90,
      readiness_level: "audit_ready",
      controls: [{
        id: "CC6.1",
        name: "Logical access",
        description: "Access control evidence",
        score: 90,
        status: "compliant",
        evidence: ["audit-event:access-reviewed"],
        gaps: [],
      }],
      metrics: {
        evidence_count: 0,
        audit_event_count: 0,
        audit_hash_count: 0,
        redaction_count: 0,
        open_findings: 0,
        critical_findings: 0,
      },
    }],
    generated_at: "2026-07-16T00:00:00Z",
    ...(trustSummary ? { trust_summary: trustSummary } : {}),
  },
  signing_key: { algorithm: "Ed25519", key_id: "key-one", public_key: "public-key" },
  verification_guide: [],
  generated_at: "2026-07-16T00:00:00Z",
});

test("renders backend-provided Trust Summary buckets", async ({ page }) => {
  await page.route("**/api/trust-center/public/demo-token", async (route) => {
    expect(route.request().headers()["x-trust-center-access"]).toBe(trustCenterAccess);
    await route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(packageResponse({
      generated_at: "2026-07-16T00:00:00Z",
      counts: { verified: 1, in_progress: 1, planned: 1 },
      verified: [{ framework: "SOC2", id: "one", name: "Access Controls", score: 90, status: "compliant" }],
      in_progress: [{ framework: "SOC2", id: "two", name: "Monitoring", score: 70, status: "partial" }],
      planned: [{ framework: "SOC2", id: "three", name: "Remediation", score: 40, status: "non_compliant" }],
    })),
    });
  });

  await page.goto("/trust-center/demo-token");

  await expect(page.getByRole("heading", { name: "Trust Summary" })).toBeVisible();
  await expect(page.getByText("Verified", { exact: true })).toBeVisible();
  await expect(page.getByText("In Progress", { exact: true })).toBeVisible();
  await expect(page.getByText("Planned", { exact: true })).toBeVisible();
  await expect(page.getByText("Verified", { exact: true }).locator("..").getByText("1", { exact: true })).toBeVisible();
  await expect(page.getByText("In Progress", { exact: true }).locator("..").getByText("1", { exact: true })).toBeVisible();
  await expect(page.getByText("Planned", { exact: true }).locator("..").getByText("1", { exact: true })).toBeVisible();
  await expect(page.getByText("Access Controls")).toBeVisible();
  await expect(page.getByText("Monitoring")).toBeVisible();
  await expect(page.getByText("Remediation")).toBeVisible();
  await expect(page.getByText("audit-event:access-reviewed")).toBeVisible();
  await expect(page.getByText(/not an independent SOC 2 Type II report or a SOC 3 report/)).toBeVisible();
  await expect(page.getByText(/no certification is implied/)).toBeVisible();
});

test("renders empty Trust Summary buckets", async ({ page }) => {
  await page.route("**/api/trust-center/public/demo-token", async (route) => {
    expect(route.request().headers()["x-trust-center-access"]).toBe(trustCenterAccess);
    await route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(packageResponse({
      generated_at: "2026-07-16T00:00:00Z",
      counts: { verified: 0, in_progress: 0, planned: 0 },
      verified: [], in_progress: [], planned: [],
    })),
    });
  });

  await page.goto("/trust-center/demo-token");

  await expect(page.getByText("Verified", { exact: true }).locator("..").getByText("0", { exact: true })).toBeVisible();
  await expect(page.getByText("In Progress", { exact: true }).locator("..").getByText("0", { exact: true })).toBeVisible();
  await expect(page.getByText("Planned", { exact: true }).locator("..").getByText("0", { exact: true })).toBeVisible();
  await expect(page.getByText("No controls in this category.")).toHaveCount(3);
});

test("supports public responses without Trust Summary", async ({ page }) => {
  await page.route("**/api/trust-center/public/demo-token", async (route) => {
    expect(route.request().headers()["x-trust-center-access"]).toBe(trustCenterAccess);
    await route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(packageResponse()),
    });
  });

  await page.goto("/trust-center/demo-token");

  await expect(page.getByText("Trust Summary is unavailable for this response.")).toBeVisible();
  await expect(page.getByText(/Calculation version: legacy_unversioned/).first()).toBeVisible();
  await expect(page.getByText("Legacy results do not establish current evidence qualification.")).toBeVisible();
});

test("shows the server evidence gate and version without reclassifying a high score", async ({ page }) => {
  const baseline = packageResponse();
  const framework = baseline.scores.frameworks[0];
  await page.route("**/api/trust-center/public/demo-token", (route) => route.fulfill({
    json: {
      ...baseline,
      scores: {
        ...baseline.scores, calculation_version: "evidence-v2", readiness_level: "monitor",
        frameworks: [{ ...framework, calculation_version: "evidence-v2", readiness_level: "monitor", controls: [{
          ...framework.controls[0], score: 99, status: "partial", gaps: ["Assessment expired; current review required"],
          evidence_assessment: { state: "blocked", reason_codes: ["stale_assessment"], required_count: 1, qualified_count: 0, as_of: "2026-09-18T00:00:00Z", valid_until: null },
        }] }],
      },
    },
  }));
  await page.goto("/trust-center/demo-token");
  await expect(page.getByText(/Calculation version: evidence-v2/).first()).toBeVisible();
  await expect(page.getByText("Evidence blocked: 0/1 requirements qualified")).toBeVisible();
  await expect(page.getByText("Assessment expired; current review required")).toBeVisible();
  await expect(page.getByText("stale_assessment", { exact: true })).toBeVisible();
  await expect(page.getByText("partial - 99%")).toBeVisible();
  await expect(page.getByText("Activity Diagnostics", { exact: true })).toBeVisible();
});

test("a failed package reload removes previously affirmative scores", async ({ page }) => {
  let fail = false;
  await page.route("**/api/trust-center/public/demo-token", (route) => route.fulfill(
    fail ? { status: 503, json: { detail: "Assessment source unavailable" } } : { json: packageResponse() },
  ));
  await page.goto("/trust-center/demo-token");
  await expect(page.getByText("AUDIT READY").first()).toBeVisible();
  fail = true;
  await page.reload();
  await expect(page.getByText("Assessment source unavailable")).toBeVisible();
  await expect(page.getByText("AUDIT READY")).toHaveCount(0);
  await expect(page.getByText("90%")).toHaveCount(0);
});

test("verifies Trust Center access and navigates signed export", async ({ page }) => {
  await page.addInitScript(() => sessionStorage.removeItem("trust-center:live-token"));
  await page.route("**/api/trust-center/public/live-token/request-access", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ email: "auditor@example.com", dev_otp: "123456" }),
    });
  });
  await page.route("**/api/trust-center/public/live-token/verify-access", async (route) => {
    expect(await route.request().postDataJSON()).toEqual({ otp: "123456" });
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ access_token: trustCenterAccess }),
    });
  });
  await page.route("**/api/trust-center/public/live-token", async (route) => {
    expect(route.request().headers()["x-trust-center-access"]).toBe(trustCenterAccess);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(packageResponse()),
    });
  });
  await page.route("**/api/trust-center/public/live-token/signed-export?framework=SOC2", async (route) => {
    expect(route.request().headers()["x-trust-center-access"]).toBe(trustCenterAccess);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ payload: { export_id: "smoke-export" }, signature: "signed" }),
    });
  });

  await page.goto("/trust-center/live-token");
  await page.getByRole("button", { name: "Send verification code" }).click();
  await expect(page.getByText("Code sent to auditor@example.com")).toBeVisible();
  await page.getByRole("button", { name: "Verify and open" }).click();
  await expect(page.getByRole("heading", { name: "Example Tenant" })).toBeVisible();

  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download SOC2 Export" }).click();
  expect((await download).suggestedFilename()).toBe("authclaw_SOC2_signed_export_smoke-export.json");
});
