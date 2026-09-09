import { expect, test } from "@playwright/test";

test("failed read-all mutation remains visible to the user", async ({ page }) => {
  const email = process.env.E2E_LOGIN_EMAIL || "admin@authclaw-lite.demo";
  const password = process.env.E2E_LOGIN_PASSWORD || "AuthClawDemo!234";
  const tenantName = process.env.E2E_LOGIN_TENANT || "AuthClaw Lite Demo";

  await page.goto("/login");
  await page.locator('input[type="email"]').fill(email);
  await page.locator('input[type="password"]').fill(password);
  await page
    .getByPlaceholder("Only needed if your email has multiple tenants")
    .fill(tenantName);
  await page.getByRole("button", { name: "Sign In" }).click();
  await page.waitForURL("/connect");

  await page.route("**/api/notifications?limit=100", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        unread_count: 1,
        items: [
          {
            id: "notification-regression",
            type: "finding_created",
            severity: "warning",
            title: "Regression notification",
            body: "Must remain unread when the mutation fails",
            link: null,
            read_at: null,
            created_at: "2026-09-07T10:00:00Z",
          },
        ],
      }),
    });
  });
  await page.route("**/api/notifications/read-all", async (route) => {
    await route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({ detail: "synthetic backend failure" }),
    });
  });

  await page.goto("/notifications");
  await expect(page.getByText("Regression notification")).toBeVisible();
  await page.getByRole("button", { name: "Mark all read" }).click();

  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "Could not mark notifications as read" }),
  ).toHaveText("Could not mark notifications as read. Please try again.");
  await expect(page.getByText("Regression notification")).toBeVisible();
});
