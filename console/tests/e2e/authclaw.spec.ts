import { test, expect } from '@playwright/test';

test.describe('AuthClaw E2E Console Verification', () => {
  test('complete app shell flow', async ({ page }) => {
    const email = process.env.E2E_LOGIN_EMAIL || 'admin@authclaw-lite.demo';
    const password = process.env.E2E_LOGIN_PASSWORD || 'AuthClawDemo!234';
    const tenantName = process.env.E2E_LOGIN_TENANT || 'AuthClaw Lite Demo';

    await page.goto('/login');
    await expect(page.locator('body')).toContainText('AuthClaw Lite');

    await page.fill('input[type="email"]', email);
    await page.fill('input[type="password"]', password);
    await page.click('button[type="submit"]');

    await page.waitForURL('/connect');
    await expect(page).toHaveURL(/.*connect/);
    await expect(page.locator('body')).toContainText('Connect Your AI App');
    await expect
      .poll(async () => {
        const response = await page.request.get('/api/auth/session');
        return response.status();
      })
      .toBe(200);
    const session = await (await page.request.get('/api/auth/session')).json();
    expect(session.tenantName).toBe(tenantName);

    await page.goto('/overview');
    await expect(page.locator('body')).toContainText('Overview');
    await expect(page.locator('body')).toContainText('Total API calls intercepted');

    await page.goto('/audit');
    await expect(page.locator('h1')).toContainText('Audit Explorer');
    await expect(page.locator('body')).toContainText(/No data available yet|Showing \d+ entries|Event Metadata/);

    const rowsCount = await page.locator('table tbody tr').count();
    if (rowsCount > 0) {
      await page.locator('table tbody tr').first().click();
      await expect(page.locator('body')).toContainText('Event Inspector');
      await expect(page.locator('body')).toContainText('Raw Event JSON');
      await page.locator('div.fixed.inset-0.bg-black\\/60').click({ force: true });
    }

    await page.goto('/agent');
    await expect(page.locator('h1')).toContainText('Compliance Agent');

    const chatInput = page.locator('input[placeholder="Ask about compliance evidence or remediation..."]');
    await expect(chatInput).toBeVisible();

    await chatInput.fill('How does GDPR apply to audit logging?');
    await page.click('form button[type="submit"]');

    await expect(page.locator('body')).toContainText('GDPR');
    await expect(page.locator('body')).toContainText(/citation|evidence|framework|audit/i);
  });
});
