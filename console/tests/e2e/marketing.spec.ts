import { expect, test } from "@playwright/test";

const canonicalPages = [
  { path: "/", title: "AuthClaw — The runtime layer for AI compliance" },
  { path: "/product", title: "Product — AuthClaw" },
  { path: "/pricing", title: "Pricing — AuthClaw" },
  { path: "/security", title: "Security & Trust — AuthClaw" },
  { path: "/company", title: "Company — AuthClaw" },
];

const legacyRedirects = [
  ["/index.html", "/"],
  ["/product.html", "/product"],
  ["/pricing.html", "/pricing"],
  ["/security.html", "/security"],
  ["/company.html", "/company"],
] as const;

test.describe("F25 public marketing routes", () => {
  for (const route of canonicalPages) {
    test(`${route.path} is public, canonical, and accessible`, async ({ page }) => {
      const response = await page.goto(route.path);
      expect(response?.status()).toBe(200);
      await expect(page).toHaveTitle(route.title);
      await expect(page.locator("main")).toHaveCount(1);
      await expect(page.locator("h1")).toHaveCount(1);
      await expect(page.locator('link[rel="canonical"]')).toHaveAttribute(
        "href",
        new RegExp(`${route.path === "/" ? "/?$" : `${route.path}$`}`)
      );
      await expect(page.locator('meta[property="og:title"]')).toHaveAttribute(
        "content",
        route.title
      );
      await expect(page.locator('meta[name="twitter:card"]')).toHaveAttribute(
        "content",
        "summary_large_image"
      );
      await expect(page.locator('a[href$=".html"]')).toHaveCount(0);
    });
  }

  for (const [legacy, canonical] of legacyRedirects) {
    test(`${legacy} redirects permanently to ${canonical}`, async ({ request }) => {
      const response = await request.get(legacy, { maxRedirects: 0 });
      expect(response.status()).toBe(308);
      expect(response.headers().location).toBe(canonical);
    });
  }

  test("desktop navigation exposes canonical active states", async ({ page }) => {
    await page.goto("/security");
    const navigation = page.getByRole("navigation", {
      name: "Primary navigation",
    });
    await expect(navigation.getByRole("link", { name: "Security" })).toHaveAttribute(
      "aria-current",
      "page"
    );
    await expect(navigation.locator('a[href$=".html"]')).toHaveCount(0);
  });

  test("mobile navigation supports state and keyboard dismissal", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/");
    const toggle = page.getByRole("button", { name: "Open menu" });
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await toggle.click();
    await expect(page.getByRole("button", { name: "Close menu" })).toHaveAttribute(
      "aria-expanded",
      "true"
    );
    await expect(
      page.getByRole("navigation", { name: "Mobile navigation" })
    ).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(toggle).toBeFocused();
  });

  test("pricing interactions expose accessible state", async ({ page }) => {
    await page.goto("/pricing");
    const monthly = page.getByRole("button", { name: "Monthly", exact: true });
    const annual = page.getByRole("button", { name: "Annual", exact: true });
    await expect(annual).toHaveAttribute("aria-pressed", "true");
    await monthly.click();
    await expect(monthly).toHaveAttribute("aria-pressed", "true");
    await expect(annual).toHaveAttribute("aria-pressed", "false");

    const question = page.getByRole("button", {
      name: /Do you mark up model tokens/,
    });
    const answer = page.locator("#faq-panel-1");
    await expect(question).toHaveAttribute("aria-expanded", "false");
    await expect(answer).toHaveAttribute("aria-hidden", "true");
    await question.click();
    await expect(question).toHaveAttribute("aria-expanded", "true");
    await expect(answer).toHaveAttribute("aria-hidden", "false");
    await page.keyboard.press("Escape");
    await expect(question).toHaveAttribute("aria-expanded", "false");
    await expect(answer).toHaveAttribute("aria-hidden", "true");
  });

  test("SEO endpoints and social image are public", async ({ page, request }) => {
    await page.goto("/");
    const imageUrl = await page
      .locator('meta[property="og:image"]')
      .getAttribute("content");
    expect(imageUrl).toBeTruthy();
    expect((await request.get(imageUrl!)).status()).toBe(200);

    const robots = await request.get("/robots.txt");
    expect(robots.status()).toBe(200);
    const robotsBody = await robots.text();
    expect(robotsBody).toContain("Sitemap:");
    expect(robotsBody).toContain("Disallow: /agent");
    expect(robotsBody).toContain("Disallow: /trust-center/");

    const sitemap = await request.get("/sitemap.xml");
    expect(sitemap.status()).toBe(200);
    const sitemapBody = await sitemap.text();
    for (const route of canonicalPages) {
      expect(sitemapBody).toContain(route.path);
    }
  });

  test("internal links resolve and page fragments exist", async ({ page, request }) => {
    const destinations = new Set<string>();
    for (const route of canonicalPages) {
      await page.goto(route.path);
      const hrefs = await page.locator("a[href]").evaluateAll((links) =>
        links.map((link) => link.getAttribute("href") || "")
      );
      for (const href of hrefs) {
        if (href.startsWith("#")) {
          await expect(page.locator(href)).toHaveCount(1);
        } else if (href.startsWith("/")) {
          destinations.add(href);
        }
      }
    }
    for (const destination of destinations) {
      expect((await request.get(destination)).status()).toBeLessThan(400);
    }
  });

  test("public pages contain no unsupported certification claim", async ({ page }) => {
    for (const route of canonicalPages) {
      await page.goto(route.path);
      await expect(page.locator("body")).not.toContainText(
        "SOC 2 Type II certified"
      );
      await expect(page.locator("body")).not.toContainText(
        "Independently audited"
      );
      await expect(page.locator("body")).not.toContainText("tamper-proof");
      await expect(page.locator("body")).not.toContainText("immutable");
      expect(
        await page.locator("table th:not([scope])").count()
      ).toBe(0);
    }
  });
});
