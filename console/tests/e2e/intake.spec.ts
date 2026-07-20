import { expect, test, type Page } from "@playwright/test";

async function fillIntake(page: Page) {
  await page.getByLabel("Name").fill("Ada Lovelace");
  await page.getByLabel("Business email").fill("ada@example.com");
  await page.getByLabel("Company").fill("Analytical Engines");
  await page.getByLabel("Role").fill("CTO");
  await page.getByLabel("Use case").fill("Govern AI traffic.");
  await page
    .getByLabel("I consent to AuthClaw processing this information for this request.")
    .check();
}

test.describe("F26 public intake", () => {
  test("demo and early-access CTAs open their canonical pages", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("link", { name: "Book a demo" }).first().click();
    await expect(page).toHaveURL(/\/demo$/);
    await expect(page.getByRole("heading", { name: "Book an AuthClaw demo" })).toBeVisible();

    await page.getByRole("link", { name: "Early Access" }).first().click();
    await expect(page).toHaveURL(/\/early-access$/);
    await expect(page.getByRole("heading", { name: "Request early access" })).toBeVisible();
  });

  test("form renders and requires explicit consent", async ({ page }) => {
    await page.goto("/demo");

    await expect(page.getByLabel("Name")).toBeVisible();
    await expect(page.getByLabel("Business email")).toBeVisible();
    await expect(page.getByLabel("Company")).toBeVisible();
    await expect(page.getByLabel("Role")).toBeVisible();
    await expect(page.getByLabel("Use case")).toBeVisible();
    await expect(page.getByLabel("Requested access")).toHaveValue("Product demo");
    await expect(page.getByRole("button", { name: "Submit request" })).toBeDisabled();
  });

  test("successful submission uses the approved demo contract", async ({ page }) => {
    let payload: Record<string, unknown> = {};
    await page.route("**/api/access-requests", async (route) => {
      payload = route.request().postDataJSON();
      await route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({
          reference: "AR-test-reference",
          status: "PENDING",
          created_at: "2026-07-20T00:00:00Z",
        }),
      });
    });
    await page.goto("/demo");
    await fillIntake(page);
    await page.getByRole("button", { name: "Submit request" }).click();

    await expect(page.getByRole("heading", { name: "Thank you" })).toBeFocused();
    await expect(page.getByText("Reference: AR-test-reference")).toBeVisible();
    expect(payload).toMatchObject({
      requested_access: "DEMO",
      source_page: "/demo",
      consent: true,
    });
  });

  test("early access submits its approved contract", async ({ page }) => {
    let payload: Record<string, unknown> = {};
    await page.route("**/api/access-requests", async (route) => {
      payload = route.request().postDataJSON();
      await route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({
          reference: "AR-early-access",
          status: "PENDING",
          created_at: "2026-07-20T00:00:00Z",
        }),
      });
    });
    await page.goto("/early-access");
    await fillIntake(page);
    await page.getByRole("button", { name: "Submit request" }).click();

    await expect(page.getByText("Reference: AR-early-access")).toBeVisible();
    expect(payload).toMatchObject({
      requested_access: "EARLY_ACCESS",
      source_page: "/early-access",
    });
  });

  for (const scenario of [
    [422, "Please check the form and try again."],
    [429, "Too many requests. Please try again later."],
    [503, "We could not submit your request. Please try again later."],
  ] as const) {
    test(`status ${scenario[0]} shows a safe accessible error`, async ({ page }) => {
      await page.route("**/api/access-requests", (route) =>
        route.fulfill({
          status: scenario[0],
          contentType: "application/json",
          body: JSON.stringify({ detail: "backend internal detail" }),
        })
      );
      await page.goto("/demo");
      await fillIntake(page);
      await page.getByRole("button", { name: "Submit request" }).click();

      const alert = page.locator(".intake-error");
      await expect(alert).toHaveText(scenario[1]);
      await expect(alert).toBeFocused();
      await expect(page.getByText("backend internal detail")).toHaveCount(0);
    });
  }
});
