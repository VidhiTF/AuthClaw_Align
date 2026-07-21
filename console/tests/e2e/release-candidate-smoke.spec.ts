import { expect, test, type Page } from "@playwright/test";

const tenantName = process.env.E2E_LOGIN_TENANT || "AuthClaw Lite Demo";
const password = process.env.E2E_LOGIN_PASSWORD || "AuthClawDemo!234";

const roles = [
  { role: "owner", email: process.env.E2E_LOGIN_EMAIL || "admin@authclaw-lite.demo", manages: true },
  { role: "admin", email: "admin-role@authclaw-lite.demo", manages: true },
  { role: "operator", email: "operator@authclaw-lite.demo", manages: false },
  { role: "viewer", email: "viewer@authclaw-lite.demo", manages: false },
] as const;

async function login(page: Page, email: string) {
  await page.goto("/login");
  await page.locator('input[type="email"]').fill(email);
  await page.locator('input[type="password"]').fill(password);
  await page.getByPlaceholder("Only needed if your email has multiple tenants").fill(tenantName);
  await page.getByRole("button", { name: "Sign In" }).click();
  await page.waitForURL(/\/(connect|overview)$/);
}

for (const identity of roles) {
  test(`${identity.role} navigation and tenant context`, async ({ page }) => {
    await login(page, identity.email);

    const session = await page.request.get("/api/auth/session");
    expect(session.status()).toBe(200);
    expect(await session.json()).toMatchObject({ role: identity.role, tenantName });
    await expect(page.getByText("Active Tenant").locator("..")).toContainText(tenantName);

    for (const route of [
      { path: "/evidence", heading: "Evidence Repository" },
      { path: "/approvals", heading: "Approvals" },
    ]) {
      await page.goto(route.path);
      await expect(page.getByRole("heading", { name: route.heading })).toBeVisible();
    }

    const gatewayLink = page.getByRole("link", { name: "Gateway", exact: true });
    const settingsLink = page.getByRole("link", { name: "Settings", exact: true });
    await expect(gatewayLink).toHaveCount(identity.manages ? 1 : 0);
    await expect(settingsLink).toHaveCount(identity.manages ? 1 : 0);

    await page.goto("/settings");
    if (identity.manages) {
      await expect(page).toHaveURL(/\/settings$/);
      await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
    } else {
      await expect(page).toHaveURL(/\/overview$/);
      await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    }
  });
}

test("owner can execute an approval decision", async ({ page }) => {
  let rejected = false;
  await page.route("**/api/approvals", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([{
        id: "approval-smoke",
        action_id: "request-smoke",
        action_description: "Release candidate smoke approval",
        action_payload: { provider: "gemini", model: "gemini-2.5-flash-lite", reason: "Policy review" },
        status: rejected ? "REJECTED" : "PENDING",
        created_at: "2026-07-21T00:00:00Z",
        expires_at: "2026-07-22T00:00:00Z",
      }]),
    });
  });
  await page.route("**/api/approvals/approval-smoke/reject", async (route) => {
    expect(route.request().method()).toBe("POST");
    rejected = true;
    await route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });

  await login(page, roles[0].email);
  await page.goto("/approvals");
  await expect(page.getByText("Policy review")).toBeVisible();
  await page.getByRole("button", { name: "Reject", exact: true }).click();
  await expect(page.getByText("REJECTED", { exact: true })).toBeVisible();
});
