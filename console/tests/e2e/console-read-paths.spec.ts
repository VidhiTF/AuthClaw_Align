import { expect, test } from "@playwright/test";

test("authenticated console read paths respond without proxy timeouts", async ({ page }) => {
  await page.goto("/login");
  await page.locator('input[type="email"]').fill(process.env.E2E_LOGIN_EMAIL || "admin@authclaw-lite.demo");
  await page.locator('input[type="password"]').fill(process.env.E2E_LOGIN_PASSWORD || "AuthClawDemo!234");
  await page.getByPlaceholder("Only needed if your email has multiple tenants").fill("AuthClaw Lite Demo");
  await page.getByRole("button", { name: "Sign In" }).click();
  await page.waitForURL("/connect");

  const started = Date.now();
  const responses = await Promise.all([
    page.request.get("/api/notifications?limit=10"),
    page.request.get("/api/compliance-scores?persist_snapshot=false"),
    page.request.get("/api/dashboard"),
  ]);

  expect(responses.map((response) => response.status())).toEqual([200, 200, 200]);
  expect(Date.now() - started).toBeLessThan(15_000);

  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.goto("/compliance");
  await page.getByRole("button", { name: /GDPR/ }).click();
  await expect(page.getByText("GDPR Control Assessments")).toBeVisible();
  await page.getByRole("button", { name: /HIPAA Security Rule/ }).click();
  await expect(page.getByText("HIPAA Control Assessments")).toBeVisible();
  expect(pageErrors).toEqual([]);
});
