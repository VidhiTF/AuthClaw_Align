import { expect, test } from "@playwright/test";

async function login(page: import("@playwright/test").Page) {
  await page.goto("/login");
  const email = page.locator('input[type="email"]');
  const password = page.locator('input[type="password"]');
  const tenant = page.getByPlaceholder("Only needed if your email has multiple tenants");
  const signIn = page.getByRole("button", { name: "Sign In" });
  await expect(email).toBeVisible();
  await expect(password).toBeVisible();
  await expect(signIn).toBeEnabled();
  await email.fill(process.env.E2E_LOGIN_EMAIL || "admin@authclaw-lite.demo");
  await password.fill(process.env.E2E_LOGIN_PASSWORD || "AuthClawDemo!234");
  await tenant.fill(process.env.E2E_LOGIN_TENANT || "AuthClaw Lite Demo");
  await expect(email).toHaveValue(process.env.E2E_LOGIN_EMAIL || "admin@authclaw-lite.demo");
  await expect(password).toHaveValue(process.env.E2E_LOGIN_PASSWORD || "AuthClawDemo!234");
  await signIn.click();
  await page.waitForURL("/connect");
}

test("gateway traffic reaches the provider and becomes audit and framework evidence", async ({ page }) => {
  await login(page);

  const testButton = page.getByRole("button", { name: /Test Gemini key/i });
  await expect(testButton).toBeEnabled({ timeout: 15_000 });
  await testButton.click();
  await expect(page.getByText("Gateway request succeeded")).toBeVisible({ timeout: 15_000 });

  await page.goto("/audit");
  await expect(page.getByRole("heading", { name: "Audit Explorer" })).toBeVisible();
  await expect(page.getByText(/Showing\s+[1-9]\d*\s+entries/)).toBeVisible();

  await page.goto("/frameworks");
  const liveInputs = page.getByText("Live Score Inputs").locator("..");
  const auditEvents = liveInputs.getByText("Audit Events", { exact: true }).locator("..");
  await expect(auditEvents).not.toContainText(/^Audit Events\s+0$/);
  const hashChainedEvents = liveInputs.getByText("Hash-Chained Events", { exact: true }).locator("..");
  await expect(hashChainedEvents).not.toContainText(/^Hash-Chained Events\s+0$/);
});
