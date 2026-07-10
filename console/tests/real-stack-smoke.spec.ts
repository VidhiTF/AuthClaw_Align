import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';
const password = 'PhaseC-Smoke-Password-123!';

type AuthSession = {
  email: string;
  token: string;
  tenantId: string;
  providerName: string;
  providerId: string;
  routeName: string;
  routeId: string;
  forbiddenRouteName?: string;
};

let ownerA: AuthSession;
let ownerB: AuthSession;
let viewerA: { email: string; token: string };
let adminA: { email: string; token: string };

async function postJson(request: APIRequestContext, path: string, data: object, token?: string) {
  const response = await request.post(`${apiBase}${path}`, {
    data,
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
  });
  return response;
}

async function getJson(request: APIRequestContext, path: string, token: string) {
  const response = await request.get(`${apiBase}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(response.ok(), await response.text()).toBeTruthy();
  return response.json();
}

async function login(request: APIRequestContext, email: string) {
  const response = await postJson(request, '/auth/login', { email, password });
  expect(response.ok(), await response.text()).toBeTruthy();
  return (await response.json()) as { access_token: string };
}

async function createGatewayKey(request: APIRequestContext, token: string, label: string) {
  const response = await postJson(
    request,
    '/api-keys',
    { name: `Phase C Gateway ${label}`, scope: 'gateway_only' },
    token,
  );
  expect(response.ok(), await response.text()).toBeTruthy();
  const body = await response.json();
  expect(body.raw_key).toMatch(/^ac_/);
  return body.raw_key as string;
}

async function seedGatewayAuditEvent(request: APIRequestContext, owner: AuthSession, label: string) {
  const rawKey = await createGatewayKey(request, owner.token, label);
  const gatewayResponse = await request.post(`${apiBase}/gateway/chat/completions`, {
    headers: { 'X-API-Key': rawKey },
    data: {
      model: 'llama-3.1-8b-instant',
      messages: [{ role: 'user', content: `Phase C audit ledger proof ${label}` }],
    },
  });
  expect(gatewayResponse.status()).toBeGreaterThanOrEqual(200);

  let event: { id?: string; event_type?: string } | null = null;
  await expect
    .poll(async () => {
      const audit = await getJson(request, '/audit/logs?limit=100', owner.token);
      event = audit.items?.find((item: { id?: string; event_type?: string }) => item.id && item.event_type) || null;
      return event?.id || null;
    }, { timeout: 20_000 })
    .not.toBeNull();
  return { eventId: event!.id!, eventType: event!.event_type! };
}

async function signupOwner(request: APIRequestContext, label: string): Promise<AuthSession> {
  const email = `phase-c-${label}@authclawsmoke.com`;
  const signup = await postJson(request, '/auth/signup', {
    email,
    password,
    first_name: 'Phase',
    last_name: `Smoke ${label}`,
    company_name: `Phase C Smoke ${label}`,
  });
  expect(signup.ok(), await signup.text()).toBeTruthy();
  const user = await signup.json();
  const { access_token: token } = await login(request, email);
  const providerName = `Phase C Provider ${label}`;
  const provider = await postJson(
    request,
    '/providers',
    {
      name: providerName,
      type: 'groq',
      api_key: `phase-c-local-provider-key-${label}`,
      config: { model: 'llama-3.1-8b-instant' },
      is_active: true,
    },
    token,
  );
  expect(provider.ok(), await provider.text()).toBeTruthy();
  const providerBody = await provider.json();
  const routeName = `Phase C Route ${label}`;
  const route = await postJson(
    request,
    '/gateway-routes',
    {
      name: routeName,
      description: 'Phase C real backend smoke route',
      provider_id: providerBody.id,
      is_default: true,
      is_active: true,
      redaction: 'mask',
      config: { model: 'llama-3.1-8b-instant' },
    },
    token,
  );
  expect(route.ok(), await route.text()).toBeTruthy();
  const routeBody = await route.json();
  return { email, token, tenantId: user.tenant_id, providerName, providerId: providerBody.id, routeName, routeId: routeBody.id };
}

async function createViewer(request: APIRequestContext, owner: AuthSession, label: string) {
  return createTenantUser(request, owner, label, 'viewer');
}

async function createTenantUser(request: APIRequestContext, owner: AuthSession, label: string, roleName: string) {
  const email = `phase-c-viewer-${label}@authclawsmoke.com`;
  const response = await postJson(
    request,
    '/users',
    { email: email.replace('viewer', roleName), password, first_name: roleName, last_name: label, role_name: roleName },
    owner.token,
  );
  expect(response.ok(), await response.text()).toBeTruthy();
  const userEmail = email.replace('viewer', roleName);
  const { access_token: token } = await login(request, userEmail);
  return { email: userEmail, token };
}

async function seedHighSeverityComplianceGap(request: APIRequestContext, owner: AuthSession) {
  const frameworks = await getJson(request, '/compliance/frameworks', owner.token);
  expect(frameworks.length).toBeGreaterThan(0);
  const assessment = await postJson(request, '/compliance/assessments/run', { framework: frameworks[0].key }, owner.token);
  expect(assessment.ok(), await assessment.text()).toBeTruthy();
  const gaps = await getJson(request, '/compliance/gaps?severity=high&limit=1', owner.token);
  expect(gaps.total).toBeGreaterThan(0);
  return gaps.items[0].id as string;
}

async function loginViaBrowser(page: Page, email: string) {
  await page.goto('/login');
  await page.locator('input[type="email"]').fill(email);
  await page.locator('input[type="password"]').fill(password);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page.getByText(/System Overview/i)).toBeVisible({ timeout: 20_000 });
}

async function authenticateWithToken(page: Page, session: AuthSession) {
  await page.goto('/login');
  await page.evaluate((token) => {
    window.localStorage.setItem('authclaw_tokens', JSON.stringify({ accessToken: token }));
  }, session.token);
  await page.goto('/overview');
  await expect(page.getByText(/System Overview/i)).toBeVisible({ timeout: 20_000 });
}

async function expectLatestGatewayTraceDetail(page: Page) {
  const traceLog = page.locator('.glass-card').filter({ hasText: /Live Trace Log/i }).first();
  await expect(traceLog.getByText(/Blocked by policy/i).first()).toBeVisible({ timeout: 20_000 });
  await traceLog.locator('tbody tr').first().click();
  const dialog = page.getByRole('dialog', { name: /Gateway Trace Event/i });
  await expect(dialog).toBeVisible({ timeout: 20_000 });
  await expect(dialog.getByText(/Policy Violations \(Blocked\)/i)).toBeVisible();
  await expect(dialog.getByText(/Original Request Sanitized Preview/i)).toBeVisible();
  await expect(dialog.getByText(/Provider Response Sanitized Preview/i)).toBeVisible();
  await expect(dialog.getByText(/token=\[redacted\]/i)).toBeVisible();
  await expect(dialog.getByText(/Credential marker blocked by smoke policy|Blocked by AuthClaw policy/i)).toBeVisible();
}

async function expectBrowserStorageDoesNotContain(page: Page, value: string) {
  const containsSecret = await page.evaluate((secret) => {
    const values = [
      ...Object.values(window.localStorage),
      ...Object.values(window.sessionStorage),
    ];
    return values.some((item) => item.includes(secret));
  }, value);
  expect(containsSecret).toBeFalsy();
}

test.describe.serial('real backend connected smoke', () => {
  test.skip(process.env.AUTHCLAW_REAL_STACK_SMOKE !== '1', 'Requires the real AuthClaw backend and database.');

  test.beforeAll(async ({ request }) => {
    const label = Date.now().toString(36);
    ownerA = await signupOwner(request, `tenant-a-${label}`);
    ownerB = await signupOwner(request, `tenant-b-${label}`);
    adminA = await createTenantUser(request, ownerA, label, 'admin');
    viewerA = await createViewer(request, ownerA, label);
  });

  test('browser authenticates and renders real dashboard, gateway, and audit/compliance data', async ({ page }) => {
    const apiCalls: string[] = [];
    page.on('request', (req) => {
      if (req.url().includes('/api/v1/')) apiCalls.push(req.url());
    });

    await loginViaBrowser(page, ownerA.email);
    await expect(page.getByText(ownerA.providerName)).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(/Providers: 1\/1/i)).toBeVisible();

    await page.goto('/gateway/providers');
    await expect(page.getByRole('heading', { name: /Gateway Providers/i })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(ownerA.providerName)).toBeVisible();
    await expect(page.getByText(/Provider Metadata/i)).toBeVisible();

    await page.goto('/gateway-routes');
    await expect(page.getByText(ownerA.routeName)).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(ownerA.providerName)).toBeVisible();
    await expect(page.getByText(/Redaction: mask/i)).toBeVisible();

    await page.goto('/audit');
    await expect(page.getByRole('heading', { level: 2, name: 'Audit & Trust Center' })).toBeVisible();
    await expect(page.getByText(/Chain Status/i)).toBeVisible({ timeout: 20_000 });

    expect(apiCalls.some((url) => url.includes('/auth/login'))).toBeTruthy();
    expect(apiCalls.some((url) => url.includes('/auth/me'))).toBeTruthy();
    expect(apiCalls.some((url) => url.includes('/providers'))).toBeTruthy();
    expect(apiCalls.some((url) => url.includes('/gateway-routes'))).toBeTruthy();
    expect(apiCalls.some((url) => url.includes('/audit/'))).toBeTruthy();
  });

  test('real browser proves overview, framework drill-down, audit verification/export, and trust center', async ({ page, request }) => {
    const compliance = await getJson(request, '/compliance/dashboard', ownerA.token);
    const { eventId: auditEventId, eventType: auditEventType } = await seedGatewayAuditEvent(request, ownerA, 'audit');
    const auditDetail = await getJson(request, `/audit/logs/${auditEventId}`, ownerA.token);
    expect(auditDetail.id).toBe(auditEventId);
    const viewerAudit = await request.get(`${apiBase}/audit/logs`, { headers: { Authorization: `Bearer ${viewerA.token}` } });
    expect(viewerAudit.status()).toBe(403);
    const crossTenantDetail = await request.get(`${apiBase}/audit/logs/${auditEventId}`, { headers: { Authorization: `Bearer ${ownerB.token}` } });
    expect([403, 404]).toContain(crossTenantDetail.status());
    await authenticateWithToken(page, ownerA);

    for (const framework of ['soc2', 'gdpr', 'hipaa'] as const) {
      await expect(page.getByText(framework, { exact: true })).toBeVisible();
      const score = compliance?.[framework]?.score;
      if (typeof score === 'number' && compliance?.[framework]?.status !== 'not_calculated') {
        await expect(page.getByText(`${score}%`).first()).toBeVisible();
      }
    }

    await page.goto('/frameworks');
    await expect(page.getByText(/Compliance Console/i)).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(/SOC 2|SOC2|GDPR|HIPAA/i).first()).toBeVisible();

    await page.goto('/audit');
    await expect(page.getByRole('heading', { level: 2, name: 'Audit & Trust Center' })).toBeVisible();
    for (const viewport of [{ width: 375, height: 900 }, { width: 768, height: 900 }, { width: 1440, height: 900 }]) {
      await page.setViewportSize(viewport);
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow).toBeLessThanOrEqual(1);
    }
    const auditTable = page.locator('tbody');
    await page.getByPlaceholder(/Search cryptographic ledger/i).fill(auditEventType);
    await expect(auditTable.getByText(auditEventType).first()).toBeVisible({ timeout: 20_000 });
    const filteredAuditResponse = page.waitForResponse(
      (response) => response.url().includes('/api/v1/audit/logs') && response.url().includes(`event_type=${encodeURIComponent(auditEventType)}`),
    );
    await page.locator('#audit-event-type-filter').selectOption(auditEventType);
    expect((await filteredAuditResponse).ok()).toBeTruthy();
    await auditTable.getByText(auditEventType).first().click();
    await expect(page.getByText(/Hash Chain Explorer/i)).toBeVisible();
    await expect(page.getByText(/Backend verification:/i)).toBeVisible();
    const recordVerifyResponse = page.waitForResponse(
      (response) => response.url().includes('/api/v1/audit/logs/') && response.url().endsWith('/verify'),
    );
    await page.getByRole('button', { name: /Verify selected record/i }).click();
    expect((await recordVerifyResponse).ok()).toBeTruthy();
    await expect(page.getByText(/Selected record verified against hash chain/i)).toBeVisible({ timeout: 20_000 });
    await page.reload();
    await expect(auditTable.getByText(auditEventType).first()).toBeVisible({ timeout: 20_000 });
    await page.getByPlaceholder(/Search cryptographic ledger/i).fill(`no-${auditEventType}`);
    await expect(page.getByText(/No audit events match/i)).toBeVisible();
    await page.getByPlaceholder(/Search cryptographic ledger/i).fill('');
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: /Export CSV/i }).click();
    const auditDownload = await download;
    expect(auditDownload.suggestedFilename()).toContain('audit');
    const auditCsvPath = await auditDownload.path();
    expect(auditCsvPath).toBeTruthy();
    const auditCsv = await readFile(auditCsvPath!, 'utf8');
    expect(auditCsv).toContain('event_type');
    expect(auditCsv).toContain(auditEventType);

    const trustOverviewResponse = page.waitForResponse((response) => response.url().includes('/api/v1/trust/overview'));
    await page.goto('/trust');
    expect((await trustOverviewResponse).ok()).toBeTruthy();
    await expect(page.getByRole('heading', { level: 2, name: 'Trust Center' })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(/Security posture/i)).toBeVisible();
    await expect(page.getByText(/Compliance posture/i)).toBeVisible();
  });

  test('real browser creates and consumes a minimized shareable Trust Center page', async ({ page, request, browser }) => {
    test.setTimeout(60_000);
    const runResponse = await postJson(
      request,
      '/reports/run',
      { report_type: 'trust_overview', filters: { scope: 'shareable-trust-smoke' }, retention_days: 7 },
      ownerA.token,
    );
    expect(runResponse.ok(), await runResponse.text()).toBeTruthy();
    const run = await runResponse.json();
    const artifact = run.artifacts?.[0];
    expect(artifact?.id).toBeTruthy();

    await authenticateWithToken(page, ownerA);
    await page.goto('/reports/artifacts');
    await expect(page.getByText(artifact.content_hash).first()).toBeVisible({ timeout: 20_000 });
    const shareResponse = page.waitForResponse((response) => response.url().includes('/api/v1/trust/share-links') && response.request().method() === 'POST');
    await page.locator('tr').filter({ hasText: artifact.content_hash }).getByRole('button', { name: /Share/i }).click();
    const sharePayload = await (await shareResponse).json();
    const shareUrl = `/trust/shared/${encodeURIComponent(sharePayload.token)}`;
    await expect(page.getByRole('heading', { name: /Trust Center share link created/i })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(`/trust/shared/${sharePayload.token}`).first()).toBeVisible();

    const externalContext = await browser.newContext();
    const sharedPage = await externalContext.newPage();
    await sharedPage.goto(shareUrl);
    await expect(sharedPage.getByText('Shared Trust Center')).toBeVisible({ timeout: 20_000 });
    await expect(sharedPage.getByText(/Evidence-supported public trust posture/i)).toBeVisible();
    await expect(sharedPage.getByText(/Security posture/i)).toBeVisible();
    await expect(sharedPage.getByText(/Compliance posture/i)).toBeVisible();
    await expect(sharedPage.getByText(artifact.content_hash)).toBeVisible();
    await expect(sharedPage.getByText(ownerA.email)).toHaveCount(0);
    await expect(sharedPage.getByText(ownerA.tenantId)).toHaveCount(0);
    await expect(sharedPage.getByText(ownerA.providerName)).toHaveCount(0);
    await expectBrowserStorageDoesNotContain(sharedPage, sharePayload.token);
    await sharedPage.reload();
    await expect(sharedPage.getByText('Shared Trust Center')).toBeVisible({ timeout: 20_000 });

    await page.keyboard.press('Escape');
    await page.reload();
    await expect(page.getByText(sharePayload.artifact_id).first()).toBeVisible({ timeout: 20_000 });
    const revokedResponse = page.waitForResponse((response) => response.url().includes(`/api/v1/trust/share-links/${sharePayload.id}/revoke`));
    await page.locator('tr').filter({ hasText: sharePayload.artifact_id }).getByRole('button', { name: /Revoke/i }).click();
    expect((await revokedResponse).ok()).toBeTruthy();
    await sharedPage.reload();
    await expect(sharedPage.getByRole('heading', { name: /Shared Trust Center unavailable/i })).toBeVisible({ timeout: 20_000 });
    await expect(sharedPage.getByText(/invalid, expired, or revoked/i)).toBeVisible();
    await externalContext.close();
  });

  test('real browser validates Azure integration configuration through backend safely', async ({ page }) => {
    await page.goto('/login');
    await page.evaluate((token) => {
      window.localStorage.setItem('authclaw_tokens', JSON.stringify({ accessToken: token }));
    }, ownerA.token);
    for (const viewport of [{ width: 375, height: 900 }, { width: 768, height: 900 }, { width: 1440, height: 900 }]) {
      await page.setViewportSize(viewport);
      await page.goto('/integrations');
      await expect(page.getByRole('heading', { name: /Cloud Integrations/i })).toBeVisible({ timeout: 20_000 });
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow).toBeLessThanOrEqual(1);
    }

    await page.getByRole('button', { name: /Add integration/i }).first().click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Provider').selectOption('azure');
    await dialog.getByLabel('Display name').fill('Azure local validation smoke');
    await dialog.getByLabel('Subscription ID').fill('00000000-0000-0000-0000-000000000001');
    await dialog.getByLabel('Tenant ID').fill('00000000-0000-0000-0000-000000000002');
    await dialog.getByLabel('Client ID').fill('00000000-0000-0000-0000-000000000003');
    await expect(dialog.getByLabel('Client secret')).toHaveValue('');
    const validateResponse = page.waitForResponse((response) => response.url().includes('/api/v1/integrations/validate'));
    await dialog.getByRole('button', { name: /^Validate$/ }).click();
    const response = await validateResponse;
    expect(response.ok()).toBeTruthy();
    const body = await response.json();
    expect(body.provider_type).toBe('azure');
    expect(body.valid).toBe(false);
    expect(JSON.stringify(body)).not.toContain('00000000-0000-0000-0000-000000000003');
    await expect(dialog.getByText(/Validation failed/i)).toBeVisible({ timeout: 20_000 });
    await expect(dialog.getByText(/missing required key/i)).toBeVisible();
    await expect(dialog.getByLabel('Client secret')).toHaveValue('');
  });

  test('real browser validates policy YAML and creates a default gateway route with policy-blocked traffic evidence', async ({ page, request }) => {
    const label = Date.now().toString(36);
    const policyName = `Phase C Policy ${label}`;
    const routeName = `Phase C UI Route ${label}`;
    const yaml = `version: authclaw.policy/v1
name: ${policyName}
description: Blocks deterministic smoke credential markers.
enabled: true
priority: 20
rules:
  - type: content_filter
    action: block
    message: Credential marker blocked by smoke policy.
    conditions:
      keywords:
        - token=
`;

    await authenticateWithToken(page, ownerA);
    await page.goto('/gateway/providers');
    await expect(page.getByRole('heading', { name: /Gateway Providers/i })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(ownerA.providerName)).toBeVisible();
    await expect(page.getByText(/Provider Metadata/i)).toBeVisible();

    await page.goto('/policies');
    await page.getByLabel(/YAML policy editor/i).fill(yaml);
    await page.getByRole('button', { name: /^Validate$/i }).click();
    await expect(page.getByText(/"valid": true/i)).toBeVisible({ timeout: 20_000 });
    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: /Save YAML/i }).click();
    await page.getByPlaceholder(/Search policies/i).fill(policyName);
    await expect(page.getByRole('heading', { name: policyName })).toBeVisible({ timeout: 20_000 });
    await page.getByLabel(/YAML policy editor/i).fill('version: authclaw.policy/v1\nname: [');
    await page.getByRole('button', { name: /^Validate$/i }).click();
    await expect(page.getByText(/"valid": false|errors/i)).toBeVisible({ timeout: 20_000 });
    const policyList = await getJson(request, '/policies?limit=100', ownerA.token);
    const policyId = policyList.items?.find((policy: { id?: string; name?: string }) => policy.name === policyName)?.id;
    expect(policyId).toMatch(/^[0-9a-f-]{36}$/i);

    await page.goto('/gateway-routes');
    await page.getByRole('button', { name: /Create Route/i }).first().click();
    await page.getByPlaceholder(/Production GPT-4 Route/i).fill(routeName);
    await page.getByPlaceholder(/Optional description/i).fill('Created through real browser acceptance');
    await page.locator('.space-y-2').filter({ hasText: /Target Provider/i }).locator('select').selectOption({ index: 1 });
    await page.getByPlaceholder(/llama-3.1-8b-instant/i).fill('llama-3.1-8b-instant');
    await page.locator('.space-y-2').filter({ hasText: /Redaction Strategy/i }).locator('select').selectOption('hash');
    const policySelect = page.locator('.space-y-2').filter({ hasText: /Attached Policy/i }).locator('select');
    await expect(policySelect.locator(`option[value="${policyId}"]`)).toHaveCount(1);
    await policySelect.selectOption(policyId || '');
    await page.getByLabel(/Default Route/i).check();
    const createRouteResponse = page.waitForResponse(
      (response) => response.url().includes('/api/v1/gateway-routes') && response.request().method() === 'POST',
    );
    const createRouteButton = page.getByRole('button', { name: /^Create Route$/i }).nth(1);
    await expect(createRouteButton).toBeEnabled();
    await createRouteButton.click();
    const routeResponse = await createRouteResponse;
    expect(routeResponse.ok(), `${await routeResponse.text()} payload=${routeResponse.request().postData()}`).toBeTruthy();
    await expect(page.getByRole('heading', { name: routeName })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(/Redaction: hash/i)).toBeVisible();
    await expect(page.getByText(`Policy: ${policyName}`)).toBeVisible({ timeout: 20_000 });
    await page.reload();
    await expect(page.getByRole('heading', { name: routeName })).toBeVisible({ timeout: 20_000 });

    await page.goto('/gateway');
    await page.getByRole('button', { name: /Create key/i }).click();
    await page.getByPlaceholder(/Type your prompt here/i).fill('A deterministic smoke token=blocked-value must be blocked before provider egress.');
    await page.getByRole('button', { name: /Send Through Gateway/i }).click();
    await expect(page.getByText('BLOCKED by Policy', { exact: true })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(/HTTP 403/i)).toBeVisible();
    await expect(page.getByText(/intercepted by the policy engine/i)).toBeVisible();
    await expect.poll(async () => {
      const response = await request.get(`${apiBase}/gateway/requests?limit=5`, {
        headers: { Authorization: `Bearer ${ownerA.token}` },
      });
      if (!response.ok()) return 0;
      return ((await response.json()) as { total?: number }).total || 0;
    }, { timeout: 20_000 }).toBeGreaterThan(0);
    await page.reload();
    await expectLatestGatewayTraceDetail(page);
  });

  test('real browser completes remediation approval queue with MFA confirmation', async ({ page, request }) => {
    test.setTimeout(120_000);
    const gapId = await seedHighSeverityComplianceGap(request, ownerA);
    await authenticateWithToken(page, ownerA);

    await page.goto('/agent');
    await expect(page.getByRole('heading', { name: /AI Assistant/i })).toBeVisible({ timeout: 20_000 });
    await page.getByPlaceholder(/Ask about policy violations/i).fill('Summarize remediation approvals.');
    await page.getByRole('button', { name: /Send message/i }).click();
    await expect(page.getByText(/Agent chat failed|intelligence backend/i).first()).toBeVisible({ timeout: 20_000 });

    await page.goto('/remediation/plans');
    await page.getByRole('button', { name: /^Generate draft$/i }).click();
    const generateDialog = page.getByRole('dialog', { name: /Generate draft remediation plan/i });
    await generateDialog.getByLabel('Source type').selectOption('gap');
    await generateDialog.getByLabel('Source ID').fill(gapId);
    const generatedResponse = page.waitForResponse((response) => response.url().includes('/api/v1/remediation/plans/generate') && response.request().method() === 'POST');
    await generateDialog.getByRole('button', { name: /^Generate draft$/i }).click();
    const generated = await generatedResponse;
    if (!generated.ok()) throw new Error(await generated.text());
    const plan = await generated.json();
    const planRow = page.locator('tr').filter({ hasText: plan.summary }).first();
    await expect(planRow).toBeVisible({ timeout: 20_000 });

    const validateResponse = page.waitForResponse((response) => response.url().includes(`/api/v1/remediation/plans/${plan.id}/validate`) && response.request().method() === 'POST');
    await planRow.getByRole('button', { name: /^Validate$/i }).click();
    expect((await validateResponse).ok()).toBeTruthy();
    await expect(planRow.getByText(/validated/i).first()).toBeVisible({ timeout: 20_000 });

    await planRow.getByRole('button', { name: /Request approval/i }).click();
    const requestDialog = page.getByRole('dialog', { name: /Request remediation approval/i });
    await requestDialog.getByLabel('Reason').fill('E3.3 browser HITL approval request.');
    const approvalResponse = page.waitForResponse((response) => response.url().includes(`/api/v1/remediation/plans/${plan.id}/request-approval`) && response.request().method() === 'POST');
    await requestDialog.getByRole('button', { name: /Request approval/i }).click();
    const approvalResult = await approvalResponse;
    if (!approvalResult.ok()) throw new Error(await approvalResult.text());
    const approval = await approvalResult.json();

    await page.evaluate(() => { window.localStorage.clear(); window.sessionStorage.clear(); });
    await loginViaBrowser(page, viewerA.email);
    await page.goto('/remediation/approvals');
    const viewerRow = page.locator('tr').filter({ hasText: plan.summary }).first();
    await expect(viewerRow).toBeVisible({ timeout: 20_000 });
    await expect(viewerRow.getByRole('button', { name: /^Approve$/i })).toBeDisabled();

    await page.evaluate(() => { window.localStorage.clear(); window.sessionStorage.clear(); });
    await loginViaBrowser(page, adminA.email);
    await page.goto('/remediation/approvals');
    await page.reload();
    const approvalRow = page.locator('tr').filter({ hasText: plan.summary }).first();
    await expect(approvalRow).toBeVisible({ timeout: 20_000 });
    await approvalRow.getByRole('button', { name: /^Detail$/i }).click();
    await expect(page.getByText(/MFA verified/i)).toBeVisible();
    await expect(page.getByText('no', { exact: true })).toBeVisible();
    await page.keyboard.press('Escape');

    await approvalRow.getByRole('button', { name: /^Approve$/i }).click();
    const approveDialog = page.getByRole('dialog', { name: /approve remediation approval/i });
    await approveDialog.getByLabel('Reason').fill('Approved after E3.3 browser MFA confirmation.');
    const missingMfa = page.waitForResponse((response) => response.url().includes(`/api/v1/remediation/approvals/${approval.id}/approve`) && response.status() === 403);
    await approveDialog.getByRole('button', { name: /^approve$/i }).click();
    await missingMfa;
    await approveDialog.getByLabel(/MFA verified for elevated approval/i).check();
    const approvedResponse = page.waitForResponse((response) => response.url().includes(`/api/v1/remediation/approvals/${approval.id}/approve`) && response.request().method() === 'POST');
    await approveDialog.getByRole('button', { name: /^approve$/i }).click();
    const approved = await approvedResponse;
    if (!approved.ok()) throw new Error(await approved.text());
    await expect(approvalRow.getByText(/approved/i).first()).toBeVisible({ timeout: 20_000 });

    const finalApproval = await getJson(request, `/remediation/approvals/${approval.id}`, adminA.token);
    expect(finalApproval.status).toBe('approved');
    expect(finalApproval.mfa_verified).toBeTruthy();
    const finalPlan = await getJson(request, `/remediation/plans/${plan.id}`, ownerA.token);
    expect(finalPlan.status).toBe('approved');

    await page.goto('/remediation/jobs');
    await expect(page.getByText(/Safe simulated\/no-op execution records/i)).toBeVisible({ timeout: 20_000 });
  });

  test('real browser proves settings users, RBAC, rate tiers, and API-key lifecycle safety', async ({ page }) => {
    const keyName = `Phase C Browser Key ${Date.now().toString(36)}`;
    await loginViaBrowser(page, ownerA.email);
    await page.goto('/settings');
    await expect(page.getByText(/User management and RBAC/i)).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(ownerA.email).first()).toBeVisible();
    await expect(page.getByText('Rate-limit tiers', { exact: true })).toBeVisible();

    await page.getByRole('button', { name: /Generate Key/i }).click();
    await page.getByPlaceholder(/Production Application Server/i).fill(keyName);
    await page.getByRole('button', { name: /Generate Token/i }).click();
    const dialog = page.getByRole('dialog', { name: /Gateway API Key Created/i });
    await expect(dialog).toBeVisible({ timeout: 20_000 });
    const rawKey = await dialog.locator('input').first().inputValue();
    expect(rawKey).toMatch(/^ac_/);
    await expectBrowserStorageDoesNotContain(page, rawKey);
    await dialog.getByRole('button', { name: /Close/i }).first().click();
    await expect.poll(async () => (
      page.locator('input').evaluateAll((inputs, secret) =>
        inputs.filter((input) => (input as HTMLInputElement).value === secret).length,
      rawKey)
    )).toBe(0);
    await page.reload();
    await expect(page.getByText(keyName)).toBeVisible({ timeout: 20_000 });
    const keyCard = page.locator('.glass-card').filter({ hasText: keyName }).first();
    await keyCard.getByRole('button', { name: /Revoke/i }).click();
    await expect(keyCard.getByText(/Revoked/i)).toBeVisible({ timeout: 20_000 });
  });

  test('real backend denies viewer writes and cross-tenant route reads', async ({ request }) => {
    ownerA.forbiddenRouteName = `Forbidden Phase C Route ${Date.now().toString(36)}`;
    const deniedCreate = await postJson(
      request,
      '/gateway-routes',
      {
        name: ownerA.forbiddenRouteName,
        provider_id: ownerA.routeId,
        redaction: 'mask',
        config: { model: 'llama-3.1-8b-instant' },
      },
      viewerA.token,
    );
    expect(deniedCreate.status()).toBe(403);

    const invalidProvider = await postJson(
      request,
      '/gateway-routes',
      {
        name: 'Cross tenant provider route',
        provider_id: ownerB.providerId,
        redaction: 'mask',
        config: { model: 'llama-3.1-8b-instant' },
      },
      ownerA.token,
    );
    expect(invalidProvider.status()).toBe(400);

    const invalidRoute = await postJson(
      request,
      '/gateway-routes',
      {
        name: '',
        provider_id: ownerA.providerId,
        redaction: 'mask',
        config: { model: 'llama-3.1-8b-instant' },
      },
      ownerA.token,
    );
    expect(invalidRoute.status()).toBe(422);

    const tenantARoutes = await request.get(`${apiBase}/gateway-routes`, {
      headers: { Authorization: `Bearer ${ownerA.token}` },
    });
    expect(tenantARoutes.ok(), await tenantARoutes.text()).toBeTruthy();
    const routesBody = await tenantARoutes.text();
    expect(routesBody).not.toContain(ownerA.forbiddenRouteName);

    const crossTenant = await request.get(`${apiBase}/gateway-routes/${ownerB.routeId}`, {
      headers: { Authorization: `Bearer ${ownerA.token}` },
    });
    expect(crossTenant.status()).toBe(404);
    expect(await crossTenant.text()).not.toContain(ownerB.routeName);
  });
});
