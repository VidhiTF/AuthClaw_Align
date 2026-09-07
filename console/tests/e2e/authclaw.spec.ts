import { test, expect } from '@playwright/test';

test.describe('AuthClaw E2E Console Verification', () => {
  test('complete app shell flow', async ({ page }) => {
    test.setTimeout(90_000);
    const email = process.env.E2E_LOGIN_EMAIL || 'admin@authclaw-lite.demo';
    const password = process.env.E2E_LOGIN_PASSWORD || 'AuthClawDemo!234';
    const tenantName = process.env.E2E_LOGIN_TENANT || 'AuthClaw Lite Demo';

    await page.goto('/login');
    await expect(page.locator('body')).toContainText('AuthClaw');

    const emailInput = page.locator('input[type="email"]');
    const passwordInput = page.locator('input[type="password"]');
    const tenantInput = page.getByPlaceholder('Only needed if your email has multiple tenants');
    const signIn = page.getByRole('button', { name: 'Sign In' });
    await expect(emailInput).toBeVisible();
    await expect(passwordInput).toBeVisible();
    await expect(signIn).toBeEnabled();
    await emailInput.fill(email);
    await passwordInput.fill(password);
    await tenantInput.fill(tenantName);
    await expect(emailInput).toHaveValue(email);
    await expect(passwordInput).toHaveValue(password);
    await expect(tenantInput).toHaveValue(tenantName);
    await signIn.click();

    await page.waitForURL('/connect');
    await expect(page).toHaveURL(/.*connect/);
    await expect(page.getByRole('heading', { name: 'Integrations' })).toBeVisible();
    const sessionResponse = await page.evaluate(async () => {
      const response = await fetch('/api/auth/session');
      return { status: response.status, body: await response.json() };
    });
    expect(sessionResponse.status).toBe(200);
    const session = sessionResponse.body;
    expect(session.tenantName).toBe(tenantName);

    const sessionCookie = (await page.context().cookies()).find((cookie) => cookie.name === 'authclaw_session');
    expect(sessionCookie).toBeTruthy();
    const sessionPayload = JSON.parse(decodeURIComponent(sessionCookie!.value));
    for (const changes of [
      { sessionId: 'forged-session' },
      { role: sessionPayload.role === 'owner' ? 'viewer' : 'owner' },
      { tenantId: 'forged-tenant' },
      { expiresAt: Date.now() + 86400000 },
    ]) {
      const value = JSON.stringify({ ...sessionPayload, ...changes });
      const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
      expect((await fetch(`${baseURL}/overview`, { headers: { cookie: `authclaw_session=${value}` } })).status).toBe(401);
    }

    await page.goto('/overview');
    await expect(page.locator('body')).toContainText('Overview');
    await expect(page.locator('body')).toContainText('Total API calls intercepted');

    for (const section of [
      { name: 'Gateway', path: '/gateway', heading: 'Gateway' },
      { name: 'Compliance', path: '/compliance', heading: 'Compliance Frameworks' },
      { name: 'Approvals', path: '/approvals', heading: 'Approvals' },
      { name: 'Audit', path: '/audit', heading: 'Audit Explorer' },
    ]) {
      const link = page.getByRole('link', { name: section.name, exact: true }).first();
      await expect(link).toHaveAttribute('href', section.path);
      await link.click();
      await expect(page).toHaveURL(new RegExp(`${section.path}$`));
      await expect(page.locator('h1')).toContainText(section.heading);
    }

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

    await page.getByRole('button', { name: 'Runs' }).click();
    await expect(page.getByText('Agent Service Remediation')).toBeVisible();
    await expect(page.getByText('Connected', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: /Ask Agen/ }).click();

    const chatInput = page.locator('input[placeholder="Ask about compliance evidence or remediation..."]');
    await expect(chatInput).toBeVisible();

    await chatInput.fill('How does GDPR apply to audit logging?');
    await page.click('form button[type="submit"]');

    await expect(page.locator('body')).toContainText('GDPR');
    await expect(page.locator('body')).toContainText(/citation|evidence|framework|audit/i);

    const inspectTrace = page.getByRole('button', { name: 'Inspect Agent Trace' }).last();
    await expect(inspectTrace).toBeVisible({ timeout: 45_000 });
    await inspectTrace.click();
    await expect(page.getByText('Agent Execution')).toBeVisible();
    await expect(page.getByText('Execution Trace')).toBeVisible();
    await expect(page.getByText('REQUEST ID')).toBeVisible();
    await expect(page.getByText(/from go_gateway/i)).toBeVisible();

    await page.request.post('/api/auth/logout');
    await page.context().addCookies([{ ...sessionCookie!, expires: -1 }]);
    expect((await page.request.get('/api/auth/session')).status()).toBe(401);
  });
});
