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
      controls: [],
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
});
