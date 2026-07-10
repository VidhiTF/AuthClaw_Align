import { test, expect, type Page, type Route } from '@playwright/test';

test.describe.configure({ mode: 'serial' });

async function fulfillJson(route: Route, json: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    headers: {
      'access-control-allow-origin': '*',
      'access-control-allow-headers': 'authorization, content-type',
      'access-control-allow-methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    },
    json,
  });
}

test('has title', async ({ page }) => {
  await page.goto('/');

  // Expect a title "to contain" a substring.
  await expect(page).toHaveTitle(/AuthClaw/i);
});

test('public homepage renders before login with real navigation and responsive shell', async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('pageerror', (error) => consoleErrors.push(error.message));

  for (const width of [375, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('/');
    await expect(page.getByRole('heading', { name: /Stop sensitive data before it reaches the model/i })).toBeVisible();
    await expect(page.getByText(/The runtime layer for AI compliance/i).first()).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBeTruthy();
    expect(await page.evaluate(() => document.querySelectorAll('a[href="#"]').length)).toBe(0);
  }

  await page.setViewportSize({ width: 375, height: 900 });
  await page.goto('/');
  await page.getByRole('button', { name: /Menu/i }).click();
  const mobileMenu = page.locator('#public-mobile-menu');
  await expect(mobileMenu.getByRole('link', { name: /Product/i })).toBeVisible();
  await mobileMenu.getByRole('link', { name: /Product/i }).click();
  await expect(page).toHaveURL(/#modules$/);
  await expect(page.locator('#public-mobile-menu')).toHaveCount(0);

  await page.goto('/');
  await page.getByRole('link', { name: /^Log in$/i }).first().click();
  await expect(page).toHaveURL(/\/login$/);
  expect(consoleErrors).toEqual([]);
  await page.setViewportSize({ width: 1280, height: 720 });
});

test('login page loads and displays form', async ({ page }) => {
  await page.goto('/login');

  // Expect login button to be visible
  await expect(page.locator('text=Sign In')).toBeVisible();
});

test('dashboard requires authentication', async ({ page }) => {
  await page.goto('/overview');
  // Next.js uses client-side routing, so it might redirect to /login
  // Since we don't have a token, it redirects us.
  await page.waitForURL('**/login');
  expect(page.url()).toContain('/login');
});

async function mockAuthenticatedUser(page: Page, role = 'admin') {
  await page.route(/.*\/auth\/me.*/, async (route: Route) => {
    await fulfillJson(route, {
        id: 'user-1',
        email: 'admin@example.com',
        first_name: 'Ava',
        last_name: 'Admin',
        tenant_id: 'tenant-1',
        role,
        roles: [role],
    });
  });
  await page.context().addInitScript(() => {
    window.localStorage.setItem('authclaw_tokens', JSON.stringify({ accessToken: 'test-token', refreshToken: 'refresh' }));
  });
  await page.goto('/login');
  await page.evaluate(() => {
    window.localStorage.setItem('authclaw_tokens', JSON.stringify({ accessToken: 'test-token', refreshToken: 'refresh' }));
  });
}

test('pdf admin console navigation aligns with safe connected surfaces', async ({ page }) => {
  await mockAuthenticatedUser(page, 'admin');

  const routeSummary = { id: 'route-1', name: 'Production GPT route', provider_id: 'provider-1', is_default: true, is_active: true, redaction: 'mask', config: { model: 'gpt-4o-mini', policy_id: 'policy-1' }, created_at: '2026-06-23T10:00:00Z' };
  const providerSummary = { id: 'provider-1', name: 'OpenAI production', provider_type: 'openai', is_active: true, key_prefix: 'prov_live' };
  const policySummary = { id: 'policy-1', name: 'Credential leakage block', description: 'Blocks demo credential markers.', is_active: true, priority: 10, rules: [], created_at: '2026-06-23T10:00:00Z', updated_at: '2026-06-23T10:00:00Z' };
  const frameworkSummary = { id: 'fw-1', key: 'soc2', version: '2026.1', name: 'SOC 2', description: 'Internal summarized framework', source_url: null, license_note: 'Internal summary', status: 'active', metadata: {}, created_at: '2026-06-23T10:00:00Z', updated_at: '2026-06-23T10:00:00Z' };
  const remediationPlan = { id: 'plan-1', tenant_id: 'tenant-1', summary: 'Rotate exposed development token', expected_impact: 'Credential leakage risk reduced.', risk_level: 'high', status: 'approved', provider: 'github', resource_ref: 'repo/authclaw', created_by: 'user-1', created_at: '2026-06-23T10:00:00Z', updated_at: '2026-06-23T10:05:00Z' };
  const remediationApproval = { id: 'approval-1', tenant_id: 'tenant-1', plan_id: 'plan-1', status: 'pending', requested_by: 'user-2', approved_by: null, required_approval_level: 'admin', approval_reason: null, rejection_reason: null, artifact_hash: 'artifact-hash-123', policy_check_hash: 'policy-hash-456', expires_at: '2026-06-23T10:30:00Z', decided_at: null, mfa_verified: false, created_at: '2026-06-23T10:01:00Z', updated_at: '2026-06-23T10:01:00Z' };
  const remediationJob = { id: 'job-1', tenant_id: 'tenant-1', plan_id: 'plan-1', approval_id: 'approval-2', dry_run_result_id: 'dry-1', status: 'executing', disabled_reason: 'Safe simulated/no-op execution record.', created_at: '2026-06-23T10:10:00Z', updated_at: '2026-06-23T10:11:00Z' };
  const reportArtifact = { id: 'artifact-1', tenant_id: 'tenant-1', run_id: 'run-1', artifact_type: 'trust_report_json', content_hash: 'sha256-content-hash', size_bytes: 4096, sanitization_version: 'authclaw.sanitizer/v1', created_at: '2026-06-23T10:00:00Z', expires_at: '2026-07-23T10:00:00Z', manifest_hash: 'manifest-hash-123' };
  let tenantPatchCalled = false;
  let rolePatchCalled = false;
  let shareCreated = false;

  await page.route(/\/api\/v1\/(?!auth\/me).*/, async (route) => fulfillJson(route, { items: [], total: 0, skip: 0, limit: 100 }));
  await page.route(/\/api\/v1\/tenants\/stats$/, async (route) => fulfillJson(route, { total: 1 }));
  await page.route(/\/api\/v1\/tenants$/, async (route) => {
    if (route.request().method() === 'PATCH') {
      tenantPatchCalled = true;
      await fulfillJson(route, { id: 'tenant-1', name: 'Acme Security', slug: 'acme', plan: 'enterprise', status: 'active', settings: {}, created_at: '2026-06-23T10:00:00Z', updated_at: '2026-06-23T10:05:00Z' });
      return;
    }
    await fulfillJson(route, { id: 'tenant-1', name: 'Acme Security', slug: 'acme', plan: 'team', status: 'active', settings: {}, created_at: '2026-06-23T10:00:00Z', updated_at: '2026-06-23T10:00:00Z' });
  });
  await page.route(/\/api\/v1\/tenants\/rate-limit-tiers$/, async (route) => fulfillJson(route, [
    { plan_name: 'free', requests_per_minute: 60, requests_per_day: 1000, api_key_requests_per_minute: 30, route_model_requests_per_minute: 30, provider_requests_per_minute: 60, concurrent_gateway_requests: 5, concurrent_streams: 1, max_body_bytes: 32768, connector_scan_concurrency: 1, connector_scan_interval_seconds: 3600, report_generation_per_hour: 5, remediation_job_concurrency: 1 },
    { plan_name: 'team', requests_per_minute: 600, requests_per_day: 10000, api_key_requests_per_minute: 300, route_model_requests_per_minute: 300, provider_requests_per_minute: 600, concurrent_gateway_requests: 25, concurrent_streams: 5, max_body_bytes: 131072, connector_scan_concurrency: 2, connector_scan_interval_seconds: 900, report_generation_per_hour: 30, remediation_job_concurrency: 2 },
    { plan_name: 'enterprise', requests_per_minute: 6000, requests_per_day: 250000, api_key_requests_per_minute: 3000, route_model_requests_per_minute: 3000, provider_requests_per_minute: 6000, concurrent_gateway_requests: 250, concurrent_streams: 50, max_body_bytes: 524288, connector_scan_concurrency: 10, connector_scan_interval_seconds: 300, report_generation_per_hour: 250, remediation_job_concurrency: 10 },
  ]));
  await page.route(/\/api\/v1\/users(?:\?.*)?$/, async (route) => fulfillJson(route, [
    { id: 'user-1', email: 'admin@example.com', first_name: 'Ava', last_name: 'Admin', tenant_id: 'tenant-1', is_active: true, roles: ['admin'], created_at: '2026-06-23T10:00:00Z', updated_at: '2026-06-23T10:00:00Z' },
    { id: 'user-2', email: 'auditor@example.com', first_name: 'Audrey', last_name: 'Audit', tenant_id: 'tenant-1', is_active: true, roles: ['auditor'], created_at: '2026-06-23T10:00:00Z', updated_at: '2026-06-23T10:00:00Z' },
  ]));
  await page.route(/\/api\/v1\/users\/user-2\/roles$/, async (route) => {
    rolePatchCalled = true;
    await fulfillJson(route, { id: 'user-2', email: 'auditor@example.com', first_name: 'Audrey', last_name: 'Audit', tenant_id: 'tenant-1', is_active: true, roles: ['analyst'], created_at: '2026-06-23T10:00:00Z', updated_at: '2026-06-23T10:05:00Z' });
  });
  await page.route(/\/api\/v1\/audit\/stats$/, async (route) => fulfillJson(route, { total_events: 1, events_by_type: { 'policy.violation': 1 }, gateway_by_status: { blocked: 1 } }));
  await page.route(/\/api\/v1\/compliance\/dashboard$/, async (route) => fulfillJson(route, {
    soc2: { score: 82, status: 'calculated' },
    gdpr: { score: 74, status: 'calculated' },
    hipaa: { score: 69, status: 'calculated' },
  }));
  await page.route(/\/api\/v1\/gateway\/requests(?:\?.*)?$/, async (route) => fulfillJson(route, {
    items: [{ id: 'gw-1', created_at: '2026-06-23T10:00:00Z', status: 'completed', model: 'gpt-4', latency_ms: 42, error_message: null }],
    total: 1,
  }));
  await page.route(/\/api\/v1\/gateway-routes(?:\?.*)?$/, async (route) => fulfillJson(route, [routeSummary]));
  await page.route(/\/api\/v1\/providers(?:\?.*)?$/, async (route) => fulfillJson(route, [providerSummary]));
  await page.route(/\/api\/v1\/gateway\/providers(?:\?.*)?$/, async (route) => fulfillJson(route, [providerSummary]));
  await page.route(/\/api\/v1\/gateway\/providers\/provider-1\/validate$/, async (route) => fulfillJson(route, { provider_id: 'provider-1', valid: true, provider_type: 'openai' }));
  await page.route(/\/api\/v1\/policies(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [policySummary], total: 1 }));
  await page.route(/\/api\/v1\/policies\/validate$/, async (route) => fulfillJson(route, { valid: true, schema_version: 'authclaw.policy/v1', normalized: { name: 'Credential leakage block' }, errors: [], warnings: [], opa: { runtime: 'adapter_seam', full_opa_runtime: false } }));
  await page.route(/\/api\/v1\/policies\/test$/, async (route) => fulfillJson(route, { allowed: false, blocked: true, action: 'block', matched_rules: [{ rule_type: 'content_filter', action: 'block', message: 'Credential marker blocked.' }], redaction_required: false, reason: 'Policy matched sample text.' }));
  await page.route(/\/api\/v1\/ai\/chat$/, async (route) => fulfillJson(route, { status: 'success', data: { role: 'assistant', content: 'Compliance assistant reviewed SOC 2 evidence-supported posture and found one approval to review.' } }));
  await page.route(/\/api\/v1\/remediation\/plans(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [remediationPlan], total: 1, skip: 0, limit: 25 }));
  await page.route(/\/api\/v1\/remediation\/approvals(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [remediationApproval, { ...remediationApproval, id: 'approval-2', status: 'approved', mfa_verified: true }], total: 2, skip: 0, limit: 25 }));
  await page.route(/\/api\/v1\/remediation\/approvals\/approval-1\/approve$/, async (route) => fulfillJson(route, { ...remediationApproval, status: 'approved', mfa_verified: true, approval_reason: 'Reviewed in console.' }));
  await page.route(/\/api\/v1\/remediation\/dry-runs(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [{ id: 'dry-1', tenant_id: 'tenant-1', plan_id: 'plan-1', artifact_id: 'artifact-1', status: 'succeeded', dry_run_type: 'no_op', output_summary: 'No external mutation attempted.', created_at: '2026-06-23T10:08:00Z', updated_at: '2026-06-23T10:08:00Z' }], total: 1, skip: 0, limit: 25 }));
  await page.route(/\/api\/v1\/remediation\/jobs(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [remediationJob], total: 1, skip: 0, limit: 25 }));
  await page.route(/\/api\/v1\/remediation\/verification-results(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [{ id: 'verify-1', tenant_id: 'tenant-1', plan_id: 'plan-1', job_id: 'job-1', status: 'succeeded', verified: true, verification_summary: 'Safe simulated verification completed.', created_at: '2026-06-23T10:12:00Z', updated_at: '2026-06-23T10:12:00Z' }], total: 1, skip: 0, limit: 25 }));
  await page.route(/\/api\/v1\/risk\/posture$/, async (route) => fulfillJson(route, {
    verdict: 'needs_review',
    summary: 'Needs review before production expansion.',
    counts: {
      probe_runs: 7,
      vulnerabilities: 5,
      open_high: 1,
      open_critical: 1,
      probe_categories_covered: ['prompt_injection', 'data_disclosure', 'credential_leakage', 'harmful_content', 'sycophancy_policy_bypass', 'policy_bypass', 'report_export_leakage'],
    },
    blockers: [{ id: 'vuln-1', title: 'Indirect instruction override needs review', severity: 'high', status: 'open' }],
    recommendations: ['Keep probe execution simulated by default.', 'Link high and critical vulnerabilities to evidence-supported remediation.'],
    evidence_summary: 'Posture derived from sanitized simulated probe runs and vulnerability register rows; auditor review required.',
    generated_at: '2026-06-24T10:00:00Z',
  }));
  await page.route(/\/api\/v1\/risk\/probes(?:\?.*)?$/, async (route) => fulfillJson(route, {
    items: [{
      id: 'probe-1',
      tenant_id: 'tenant-1',
      name: 'Prompt injection guardrail probe',
      category: 'prompt_injection',
      status: 'completed',
      target_surface: 'gateway',
      model_target: 'route-selected model',
      execution_mode: 'simulated',
      owner_user_id: 'user-1',
      started_at: '2026-06-24T09:00:00Z',
      completed_at: '2026-06-24T09:01:00Z',
      safe_prompt_preview: 'Sanitized simulated prompt injection probe preview; raw content removed.',
      result_summary: 'Simulated prompt-injection checks found one needs-review bypass pattern.',
      risk_score: 72,
      probes_total: 10,
      blocked_count: 9,
      allowed_count: 1,
      vulnerability_count: 1,
      evidence: { source: 'safe_demo_seed', execution_mode: 'simulated' },
      results: [{
        id: 'result-1',
        tenant_id: 'tenant-1',
        probe_run_id: 'probe-1',
        category: 'prompt_injection',
        target_surface: 'gateway',
        status: 'blocked',
        severity: 'high',
        confidence: 85,
        evidence_summary: 'Sanitized prompt injection result from deterministic local probe runner.',
        sanitized_input_summary: 'Local fixture for prompt injection; raw prompt removed.',
        sanitized_output_summary: 'Blocked or summarized response path only; raw provider output absent.',
        raw_payload_stored: false,
        created_at: '2026-06-24T09:00:00Z',
        updated_at: '2026-06-24T09:01:00Z',
      }],
      raw_payload_stored: false,
      created_at: '2026-06-24T09:00:00Z',
      updated_at: '2026-06-24T09:01:00Z',
    }],
    total: 1,
    skip: 0,
    limit: 50,
  }));
  await page.route(/\/api\/v1\/risk\/vulnerabilities(?:\?.*)?$/, async (route) => fulfillJson(route, {
    items: [{
      id: 'vuln-1',
      tenant_id: 'tenant-1',
      probe_run_id: 'probe-1',
      remediation_plan_id: 'rem-1',
      category: 'prompt_injection',
      title: 'Indirect instruction override needs review',
      description: 'A synthetic probe indicated a route could over-weight untrusted instructions.',
      severity: 'high',
      status: 'open',
      owner_user_id: 'user-1',
      confidence: 85,
      due_date: null,
      evidence_summary: 'Evidence-supported finding from simulated prompt-injection probe; raw content removed.',
      remediation_summary: 'Strengthen instruction hierarchy and attach remediation plan before broader rollout.',
      first_seen_at: '2026-06-24T09:00:00Z',
      last_seen_at: '2026-06-24T09:01:00Z',
      created_at: '2026-06-24T09:00:00Z',
      updated_at: '2026-06-24T09:01:00Z',
    }],
    total: 1,
    skip: 0,
    limit: 50,
  }));
  await page.route(/\/api\/v1\/risk\/probes\/run$/, async (route) => fulfillJson(route, {
    id: 'probe-2',
    tenant_id: 'tenant-1',
    name: 'Prompt injection simulated probe',
    category: 'prompt_injection',
    status: 'completed',
    target_surface: 'gateway',
    model_target: 'route-selected model',
    execution_mode: 'simulated',
    owner_user_id: 'user-1',
    started_at: '2026-06-24T09:10:00Z',
    completed_at: '2026-06-24T09:11:00Z',
    safe_prompt_preview: 'Simulated prompt injection probe; raw payload removed.',
    result_summary: 'Simulated probe completed without external attack execution.',
    risk_score: 40,
    probes_total: 3,
    blocked_count: 2,
    allowed_count: 1,
    vulnerability_count: 0,
    evidence: { source: 'manual_simulated_probe', execution_mode: 'simulated' },
    results: [],
    raw_payload_stored: false,
    created_at: '2026-06-24T09:10:00Z',
    updated_at: '2026-06-24T09:11:00Z',
  }));
  await page.route(/\/api\/v1\/risk\/seed-demo$/, async (route) => fulfillJson(route, { probe_runs_created: 7, probe_results_created: 7, vulnerabilities_created: 5, posture_snapshots_created: 1 }));
  await page.route(/\/api\/v1\/compliance\/frameworks(?:\?.*)?$/, async (route) => fulfillJson(route, [frameworkSummary]));
  await page.route(/\/api\/v1\/compliance\/assessments(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [], total: 0, skip: 0, limit: 20 }));
  await page.route(/\/api\/v1\/audit\/logs(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [{ id: 'audit-1', created_at: '2026-06-23T10:00:00Z', event_type: 'gateway.request', action: 'recorded', resource: 'gateway', resource_id: 'gw-1', user_id: null, metadata: { status: 'recorded' }, previous_hash: '0000000000000000', integrity_hash: 'hash-current-1234567890' }], total: 1 }));
  await page.route(/\/api\/v1\/audit\/verify$/, async (route) => fulfillJson(route, { status: 'intact', scanned_records: 12, missing_records: 0, tampered_records: 0, chain_breaks: 0 }));
  await page.route(/\/api\/v1\/trust\/overview$/, async (route) => fulfillJson(route, {
    tenant_id: 'tenant-1',
    generated_at: '2026-06-23T10:00:00Z',
    language: 'evidence-supported posture',
    security_posture: { tenant_id: 'tenant-1', generated_at: '2026-06-23T10:00:00Z', language: 'review required', posture: 'evidence-supported posture', counts: {}, status_counts: {}, severity_counts: {}, freshness: {} },
    compliance_posture: { tenant_id: 'tenant-1', generated_at: '2026-06-23T10:00:00Z', language: 'review required', posture: 'needs review', counts: {}, status_counts: {}, severity_counts: {}, freshness: {} },
    remediation_posture: { tenant_id: 'tenant-1', generated_at: '2026-06-23T10:00:00Z', language: 'review required', posture: 'needs review', counts: {}, status_counts: {}, severity_counts: {}, freshness: {} },
    integration_health: { tenant_id: 'tenant-1', generated_at: '2026-06-23T10:00:00Z', language: 'review required', posture: 'healthy', counts: {}, status_counts: {}, severity_counts: {}, freshness: {} },
  }));
  await page.route(/\/api\/v1\/trust\/audit-export-verification-states$/, async (route) => fulfillJson(route, { generated_at: '2026-06-23T10:00:00Z', language: 'review states only', states: [{ state: 'Verified', severity: 'info', meaning: 'Package verification succeeded.' }, { state: 'Tampered', severity: 'critical', meaning: 'Package content changed.' }] }));
  await page.route(/\/api\/v1\/reports\/artifacts(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [reportArtifact], total: 1, skip: 0, limit: 50 }));
  await page.route(/\/api\/v1\/reports\/artifacts\/artifact-1\/manifest$/, async (route) => fulfillJson(route, { id: 'manifest-1', tenant_id: 'tenant-1', artifact_id: 'artifact-1', manifest_json: { schema: 'authclaw.audit.export/v1' }, manifest_hash: 'manifest-hash-123', hash_algorithm: 'sha256', created_at: '2026-06-23T10:00:00Z' }));
  await page.route(/\/api\/v1\/trust\/share-links(?:\?.*)?$/, async (route) => {
    if (route.request().method() === 'POST') {
      shareCreated = true;
      await fulfillJson(route, { id: 'share-1', tenant_id: 'tenant-1', artifact_id: 'artifact-1', scope: { artifact_id: 'artifact-1' }, created_by: 'user-1', expires_at: '2026-07-01T10:00:00Z', revoked_at: null, max_downloads: 5, token: 'share-token-once' }, 201);
      return;
    }
    await fulfillJson(route, { items: [{ id: 'share-0', tenant_id: 'tenant-1', artifact_id: 'artifact-1', scope: {}, created_by: 'user-1', expires_at: '2026-07-01T10:00:00Z', revoked_at: null, max_downloads: 5 }], total: 1, skip: 0, limit: 50 });
  });
  await page.route(/\/api\/v1\/integrations(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [], total: 0 }));
  await page.route(/\/api\/v1\/integrations\/health$/, async (route) => fulfillJson(route, { registered_providers: [], circuit_breakers: {}, items: [] }));
  const generatedGatewayKey = 'ac_testgatewaykey1234567890abcdef';
  await page.route(/\/api\/v1\/api-keys(?:\?.*)?$/, async (route) => {
    if (route.request().method() === 'POST') {
      await fulfillJson(route, { id: 'api-key-1', name: 'Agent key', key_prefix: 'ac_testgate', raw_key: generatedGatewayKey, is_active: true, created_at: '2026-06-24T10:00:00Z' }, 201);
      return;
    }
    await fulfillJson(route, { items: [], total: 0, skip: 0, limit: 100 });
  });
  await page.route(/\/api\/v1\/api-keys\/api-key-1\/revoke$/, async (route) => fulfillJson(route, { id: 'api-key-1', name: 'Agent key', key_prefix: 'ac_testgate', is_active: false, created_at: '2026-06-24T10:00:00Z' }));

  await page.goto('/overview');
  for (const label of ['Overview', 'Gateway', 'Policies & Guardrails', 'Agent & Remediation', 'Frameworks', 'Audit & Trust Center', 'Risk & Red Teaming', 'Integrations', 'Settings']) {
    await expect(page.getByRole('link', { name: label })).toBeVisible();
  }
  await expect(page.getByText(/Evidence-supported posture/i)).toBeVisible();
  await expect(page.getByText(/Open Approvals/i)).toBeVisible();

  await page.goto('/gateway');
  await expect(page.getByText(/Route and Provider Configuration/i)).toBeVisible();
  await expect(page.getByText(/Redaction Mode/i)).toBeVisible();
  await expect(page.getByText(/Production GPT route/i)).toBeVisible();
  for (const label of ['Providers', 'Routes', 'API Keys', 'Traffic']) {
    await expect(page.getByRole('link', { name: label, exact: true })).toBeVisible();
  }

  await page.goto('/gateway/providers');
  await expect(page.getByText(/Gateway Providers/i)).toBeVisible();
  await expect(page.getByText(/Provider Metadata/i)).toBeVisible();
  await expect(page.getByText(/OpenAI production/i)).toBeVisible();

  await page.goto('/gateway/routes');
  await expect(page.getByText(/Gateway Routes/i)).toBeVisible();
  await expect(page.getByText(/Production GPT route/i)).toBeVisible();
  await expect(page.getByText(/Policy: Credential leakage block/i)).toBeVisible();

  await page.goto('/gateway/api-keys');
  await expect(page.getByText(/Gateway API Keys/i)).toBeVisible();
  await expect(page.getByText(/Create AuthClaw Gateway Key/i)).toBeVisible();

  await page.goto('/gateway/traffic');
  await expect(page.getByText(/Gateway Traffic/i)).toBeVisible();
  await expect(page.getByText(/Traffic Inspector/i)).toBeVisible();

  await page.goto('/policies');
  await expect(page.getByText(/Prompt injection/i)).toBeVisible();
  await expect(page.getByText('Credential leakage', { exact: true })).toBeVisible();
  await expect(page.getByText(/YAML policy-as-code/i)).toBeVisible();
  await page.getByRole('button', { name: /^Validate$/i }).click();
  const validationResult = page.getByText('Validation result', { exact: true }).locator('xpath=..');
  await expect(validationResult.getByText(/authclaw.policy\/v1/i)).toBeVisible();
  await page.getByRole('button', { name: /^Test Prompt$/i }).click();
  const policyTestResult = page.getByText('Test result', { exact: true }).locator('xpath=..');
  await expect(policyTestResult.getByText(/Credential marker blocked/i)).toBeVisible();
  await expect(page.getByText(/Backend validated on save/i)).toBeVisible();

  await page.goto('/agent-remediation');
  await expect(page.getByText(/Safe execution only/i)).toBeVisible();
  await expect(page.getByText(/^Assistant$/i)).toBeVisible();
  await expect(page.getByText(/End-to-end approval workflow/i)).toBeVisible();
  for (const label of ['Pending', 'User reviews', 'MFA confirmation', 'Approved', 'Executing', 'Success / Failure']) {
    await expect(page.getByText(label, { exact: true })).toBeVisible();
  }
  await expect(page.getByRole('link', { name: /^Open$/i }).first()).toBeVisible();

  await page.goto('/agent');
  await page.getByPlaceholder(/Ask about policy/i).fill('Summarize SOC2 posture');
  await page.getByRole('button', { name: /Send message/i }).click();
  await expect(page.getByText(/Compliance assistant reviewed SOC 2/i)).toBeVisible();

  await page.goto('/remediation/approvals');
  await expect(page.getByRole('link', { name: /Rotate exposed development token/i }).first()).toBeVisible();
  await expect(page.getByText(/artifact artifact-hash-123/i).first()).toBeVisible();
  await page.getByRole('button', { name: /^Approve$/i }).first().click();
  await page.getByLabel(/Reason/i).fill('Reviewed in console.');
  await page.getByLabel(/MFA verified for elevated approval/i).check();
  await page.getByRole('button', { name: /^approve$/i }).click();

  await page.goto('/remediation/jobs');
  await expect(page.getByText('executing', { exact: true })).toBeVisible();
  await expect(page.getByText(/Safe simulated verification completed/i)).toBeVisible();

  await page.goto('/frameworks');
  await expect(page.getByText(/SOC 2/i)).toBeVisible();
  await expect(page.getByText(/View controls/i)).toBeVisible();

  await page.goto('/audit');
  await expect(page.getByText('Verified', { exact: true })).toBeVisible();
  await expect(page.getByText(/12 scanned/i)).toBeVisible();
  await expect(page.getByRole('button', { name: /Verify Integrity/i })).toBeVisible();
  await page.getByRole('table').getByText(/gateway.request/i).click();
  await expect(page.getByText(/Backend verification: Verified/i)).toBeVisible();

  await page.goto('/reports/artifacts');
  await expect(page.getByText(/Artifact metadata/i)).toBeVisible();
  await expect(page.getByText(/Shareable Trust Center links/i)).toBeVisible();
  await page.getByRole('button', { name: /^Share$/i }).click();
  await expect(page.getByRole('heading', { name: /Trust Center share link created/i })).toBeVisible();
  await expect(page.getByText(/share-token-once/i)).toBeVisible();
  expect(shareCreated).toBeTruthy();

  await page.goto('/risk');
  await expect(page.getByText(/Go \/ No-Go Posture/i)).toBeVisible();
  await expect(page.getByText('Vulnerability Register', { exact: true })).toBeVisible();
  await expect(page.getByText(/Prompt injection guardrail probe/i)).toBeVisible();
  await expect(page.getByText(/Indirect instruction override needs review/i).first()).toBeVisible();
  await expect(page.getByText(/Backend gap|raw_provider_payload|vault:\/\/|gsk_|sk-|guaranteed compliant|audit-ready guaranteed/i)).toHaveCount(0);

  await page.goto('/settings');
  await expect(page.getByText(/Organization Profile/i)).toBeVisible();
  await expect(page.getByText(/Tenant Administration/i)).toBeVisible();
  await expect(page.getByText(/User management and RBAC/i)).toBeVisible();
  await expect(page.getByText('Rate-limit tiers', { exact: true })).toBeVisible();
  await expect(page.locator('input[value="Acme Security"]')).toBeVisible();
  await page.getByLabel(/Rate-limit tier/i).selectOption('enterprise');
  await page.getByRole('button', { name: /^Save Tenant$/i }).click();
  expect(tenantPatchCalled).toBeTruthy();
  await page.getByLabel(/Role for auditor@example.com/i).selectOption('analyst');
  await expect.poll(() => rolePatchCalled).toBeTruthy();
  await page.getByRole('button', { name: /^Generate Key$/i }).first().click();
  await page.getByPlaceholder(/Production Application Server/i).fill('Agent key');
  await page.getByRole('button', { name: /^Generate Token$/i }).click();
  await expect(page.getByRole('dialog', { name: /Gateway API Key Created/i })).toBeVisible();
  const generatedKeyInput = page.locator(`input[value="${generatedGatewayKey}"]`);
  await expect(generatedKeyInput).toHaveAttribute('type', 'password');
  await page.getByTitle('Show API key').click();
  await expect(generatedKeyInput).toHaveAttribute('type', 'text');
  await page.getByTitle('Copy API key').click();
  await expect(page.getByText(/Secret Key Generated/i)).toHaveCount(0);

  await expect(page.getByText(/SuperSecret|raw_provider_payload|vault:\/\/|certified|guaranteed compliant|audit-ready guaranteed|Client IP/i)).toHaveCount(0);
});

const integration = {
  id: '11111111-1111-1111-1111-111111111111',
  tenant_id: 'tenant-1',
  provider_type: 'aws',
  target_identifier: '123456789012',
  display_name: 'AWS prod',
  status: 'active',
  vault_reference_id: 'authclaw/tenants/tenant-1/integrations/1111',
  last_sync_at: '2026-06-20T10:00:00Z',
  last_sync_finding_count: 3,
  error_message: null,
  created_at: '2026-06-20T09:00:00Z',
  updated_at: '2026-06-20T10:00:00Z',
};

const finding = {
  id: '22222222-2222-2222-2222-222222222222',
  integration_id: integration.id,
  provider_type: 'aws',
  dedup_hash: 'abc123def4567890',
  external_id: 'securityhub-1',
  resource_id: 'arn:aws:s3:::prod-data',
  title: 'Public S3 bucket',
  description: 'Bucket allows public read access.',
  remediation_instructions: 'Enable S3 block public access.',
  severity: 'critical',
  status: 'active',
  resolved_at: null,
  created_at: '2026-06-20T09:30:00Z',
  updated_at: '2026-06-20T10:30:00Z',
  compliance_tags: ['SOC2'],
  service: 's3',
};

test('integrations list renders API data and health', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await page.route(/\/api\/v1\/integrations(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [integration], total: 1 }));
  await page.route(/\/api\/v1\/integrations\/health$/, async (route) => fulfillJson(route, {
      registered_providers: ['aws'],
      circuit_breakers: { aws: { state: 'closed' } },
      items: [{ integration_id: integration.id, provider_type: 'aws', status: 'active', worker_visibility: 'event_scheduled', registered_connector_available: true, circuit_breaker_state: { state: 'closed' } }],
    }));

  await page.goto('/integrations');

  await expect(page.getByText('AWS prod')).toBeVisible();
  await expect(page.getByText('123456789012')).toBeVisible();
  await expect(page.getByText('registered')).toBeVisible();
});

test('add integration does not display secret values and clears credential fields after validation', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await page.route(/\/api\/v1\/integrations(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [], total: 0 }));
  await page.route(/\/api\/v1\/integrations\/health$/, async (route) => fulfillJson(route, { registered_providers: [], circuit_breakers: {}, items: [] }));
  await page.route(/\/api\/v1\/integrations\/validate$/, async (route) => fulfillJson(route, { provider_type: 'aws', valid: true, missing_permissions: [] }));

  await page.goto('/integrations');
  await page.getByRole('button', { name: /^add integration$/i }).first().click();
  await page.getByLabel(/aws account id/i).fill('123456789012');
  await page.getByLabel(/access key/i).fill('AKIAIOSFODNN7EXAMPLE');
  await page.getByLabel(/secret key/i).fill('super-secret-value');
  await page.getByRole('button', { name: /^validate$/i }).click();

  const dialog = page.getByRole('dialog', { name: /add cloud integration/i });
  await expect(dialog.getByText('Credentials valid', { exact: true })).toBeVisible();
  await expect(page.getByLabel(/access key/i)).toHaveValue('');
  await expect(page.getByLabel(/secret key/i)).toHaveValue('');
  await expect(page.getByText('super-secret-value')).toHaveCount(0);
});

test('validation result renders missing permissions safely', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await page.route(/\/api\/v1\/integrations(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [], total: 0 }));
  await page.route(/\/api\/v1\/integrations\/health$/, async (route) => fulfillJson(route, { registered_providers: [], circuit_breakers: {}, items: [] }));
  await page.route(/\/api\/v1\/integrations\/validate$/, async (route) => fulfillJson(route, { provider_type: 'github', valid: false, error_code: '[redacted] missing scope', missing_permissions: ['security_events:read'] }));

  await page.goto('/integrations');
  await page.getByRole('button', { name: /^add integration$/i }).first().click();
  await page.locator('select').first().selectOption('github');
  await page.getByLabel(/org or repo target/i).fill('acme');
  await page.getByLabel(/github token/i).fill('ghp_supersecretsecretsecretsecret');
  await page.getByRole('button', { name: /^validate$/i }).click();

  const dialog = page.getByRole('dialog', { name: /add cloud integration/i });
  await expect(dialog.getByText('Validation failed', { exact: true })).toBeVisible();
  await expect(page.getByText('security_events:read')).toBeVisible();
  await expect(page.getByText('ghp_supersecretsecretsecretsecret')).toHaveCount(0);
});

test('manual sync calls API and shows queued state', async ({ page }) => {
  await mockAuthenticatedUser(page);
  let syncCalled = false;
  await page.route(/\/api\/v1\/integrations(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [integration], total: 1 }));
  await page.route(/\/api\/v1\/integrations\/health$/, async (route) => fulfillJson(route, { registered_providers: ['aws'], circuit_breakers: {}, items: [] }));
  await page.route(`**/api/v1/integrations/${integration.id}/sync`, async (route) => {
    syncCalled = true;
    await fulfillJson(route, { integration_id: integration.id, status: 'accepted', queued: true }, 202);
  });

  await page.goto('/integrations');
  await page.getByRole('button', { name: /^sync$/i }).click();

  await expect(page.getByRole('button', { name: /queued/i })).toBeVisible();
  expect(syncCalled).toBeTruthy();
});

test('read-only users cannot access integration write actions', async ({ page }) => {
  await mockAuthenticatedUser(page, 'viewer');
  await page.route(/\/api\/v1\/integrations(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [integration], total: 1 }));
  await page.route(/\/api\/v1\/integrations\/health$/, async (route) => fulfillJson(route, { registered_providers: ['aws'], circuit_breakers: {}, items: [] }));

  await page.goto('/integrations');

  await expect(page.getByText('write actions are disabled')).toBeVisible();
  await expect(page.getByRole('button', { name: /add integration/i })).toBeDisabled();
  await expect(page.getByRole('button', { name: /^sync$/i })).toBeDisabled();
});

test('findings table renders normalized findings and filters call API with params', async ({ page }) => {
  await mockAuthenticatedUser(page);
  let requestedUrl = '';
  await page.route(/\/api\/v1\/integrations(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [integration], total: 1 }));
  await page.route(/\/api\/v1\/findings(?:\?.*)?$/, async (route) => {
    requestedUrl = route.request().url();
    await fulfillJson(route, { items: [finding], total: 1, skip: 0, limit: 25 });
  });

  await page.goto('/findings');
  await expect(page.getByText('Public S3 bucket')).toBeVisible();
  await page.getByLabel(/severity/i).selectOption('critical');
  await expect.poll(() => requestedUrl).toContain('severity=critical');
});

test('finding detail excludes raw payload and status update works', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await page.route(/\/api\/v1\/integrations(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [integration], total: 1 }));
  await page.route(/\/api\/v1\/findings(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [finding], total: 1, skip: 0, limit: 25 }));
  await page.route(`**/api/v1/findings/${finding.id}`, async (route) => fulfillJson(route, { ...finding, status: 'suppressed' }));
  page.on('dialog', (dialog) => dialog.accept());

  await page.goto('/findings');
  await page.getByRole('button', { name: /detail/i }).click();

  await expect(page.getByText('Bucket allows public read access.')).toBeVisible();
  await expect(page.getByText(/Raw provider payloads/)).toBeVisible();
  await expect(page.getByText('raw_payload')).toHaveCount(0);
  await page.getByRole('button', { name: /suppress/i }).last().click();
  await expect(page.locator('[data-slot="badge"]').filter({ hasText: /^suppressed$/ })).toBeVisible();
});

const framework = {
  id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  key: 'soc2',
  version: '2026',
  name: 'SOC 2',
  description: 'Trust services criteria summary.',
  source_url: null,
  license_note: 'AuthClaw curated summary',
  status: 'active',
  metadata: {},
  control_count: 1,
  created_at: '2026-06-20T09:00:00Z',
  updated_at: '2026-06-20T10:00:00Z',
};

const control = {
  id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
  framework_id: framework.id,
  control_code: 'SOC2-SEC-ACCESS',
  title: 'Logical access protection',
  summary: 'Access control review for privileged systems.',
  domain: 'security',
  category: 'access',
  severity_weight: 3,
  requires_review: true,
  sort_order: 1,
  metadata: {},
  requirements: [{ id: 'req-1', requirement_key: 'CC6.1', summary: 'Review access evidence.', evidence_expectation: 'User and policy evidence.', sort_order: 1 }],
  created_at: '2026-06-20T09:00:00Z',
  updated_at: '2026-06-20T10:00:00Z',
};

const assessment = {
  id: 'cccccccc-cccc-cccc-cccc-cccccccccccc',
  tenant_id: 'tenant-1',
  framework_id: framework.id,
  framework_key: 'soc2',
  status: 'completed',
  score: 74,
  score_band: 'at_risk',
  started_at: '2026-06-20T11:00:00Z',
  completed_at: '2026-06-20T11:01:00Z',
  inputs_hash: 'hash',
  explanation: 'Evidence-supported posture needs review.',
  control_results: [{ id: 'result-1', tenant_id: 'tenant-1', assessment_id: 'cccccccc-cccc-cccc-cccc-cccccccccccc', control_id: control.id, score: 74, score_band: 'at_risk', evidence_count: 1, gap_count: 1, explanation: 'One gap detected.', metadata: {}, control_code: control.control_code, control_title: control.title, created_at: '2026-06-20T11:00:00Z', updated_at: '2026-06-20T11:00:00Z' }],
  gaps: [],
  created_at: '2026-06-20T11:00:00Z',
  updated_at: '2026-06-20T11:00:00Z',
};

const mapping = {
  id: 'dddddddd-dddd-dddd-dddd-dddddddddddd',
  tenant_id: 'tenant-1',
  finding_id: finding.id,
  control_id: control.id,
  rule_id: 's3_public_access',
  confidence: 0.92,
  mapping_source: 'deterministic',
  review_status: 'needs_review',
  override_reason: null,
  control_code: control.control_code,
  control_title: control.title,
  framework_key: 'soc2',
  created_at: '2026-06-20T11:00:00Z',
  updated_at: '2026-06-20T11:00:00Z',
};

const evidence = {
  id: 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee',
  tenant_id: 'tenant-1',
  control_id: control.id,
  finding_id: finding.id,
  integration_id: integration.id,
  audit_log_id: null,
  mapping_id: mapping.id,
  source_type: 'finding_mapping',
  status: 'active',
  safe_summary: 'Normalized finding evidence. token=super-secret-value raw_provider_payload removed.',
  proof_hash: 'abcdef1234567890',
  freshness_expires_at: '2026-07-20T11:00:00Z',
  metadata: {},
  control_code: control.control_code,
  framework_key: 'soc2',
  created_at: '2026-06-20T11:00:00Z',
  updated_at: '2026-06-20T11:00:00Z',
};

const gap = {
  id: 'ffffffff-ffff-ffff-ffff-ffffffffffff',
  tenant_id: 'tenant-1',
  assessment_id: assessment.id,
  control_id: control.id,
  evidence_id: evidence.id,
  mapping_id: mapping.id,
  finding_id: finding.id,
  gap_type: 'needs_review',
  severity: 'high',
  reason: 'Mapping requires human review before audit preparation.',
  evidence_status: 'active',
  metadata: {},
  control_code: control.control_code,
  framework_key: 'soc2',
  created_at: '2026-06-20T11:00:00Z',
  updated_at: '2026-06-20T11:00:00Z',
};

const recommendation = {
  id: gap.id,
  tenant_id: 'tenant-1',
  control_id: control.id,
  gap_id: gap.id,
  finding_id: finding.id,
  severity: 'high',
  status: 'review_recommended',
  title: 'Review needs review',
  summary: gap.reason,
  control_code: control.control_code,
  framework_key: 'soc2',
  created_at: '2026-06-20T11:00:00Z',
};

const knowledgeDocument = {
  id: '99999999-9999-9999-9999-999999999999',
  tenant_id: null,
  framework_id: framework.id,
  source_type: 'control_summary',
  title: 'SOC2 access control summary',
  source_url: null,
  license_status: 'summary_only',
  trust_level: 'curated',
  checksum: 'abc',
  status: 'active',
  ingested_by: null,
  metadata: {},
  chunk_count: 2,
  chunks: [],
  created_at: '2026-06-20T11:00:00Z',
  updated_at: '2026-06-20T11:00:00Z',
};

async function mockComplianceApi(page: Page) {
  await page.route(/\/api\/v1\/compliance\/frameworks\/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\/controls(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [control], total: 1, skip: 0, limit: 200 }));
  await page.route(/\/api\/v1\/compliance\/frameworks\/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa$/, async (route) => fulfillJson(route, framework));
  await page.route(/\/api\/v1\/compliance\/frameworks(?:\?.*)?$/, async (route) => fulfillJson(route, [framework]));
  await page.route(/\/api\/v1\/compliance\/controls\/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb$/, async (route) => fulfillJson(route, control));
  await page.route(/\/api\/v1\/compliance\/assessments(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [assessment], total: 1, skip: 0, limit: 20 }));
  await page.route(/\/api\/v1\/compliance\/mappings(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [mapping], total: 1, skip: 0, limit: 100 }));
  await page.route(/\/api\/v1\/compliance\/evidence(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [evidence], total: 1, skip: 0, limit: 25 }));
  await page.route(/\/api\/v1\/compliance\/gaps(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [gap], total: 1, skip: 0, limit: 25 }));
  await page.route(/\/api\/v1\/compliance\/recommendations(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [recommendation], total: 1, skip: 0, limit: 100, status: 'derived_from_existing_gaps' }));
  await page.route(/\/api\/v1\/compliance\/knowledge(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [knowledgeDocument], total: 1, skip: 0, limit: 100 }));
  await page.route(/\/api\/v1\/compliance\/knowledge\/ingest$/, async (route) => fulfillJson(route, { documents_seen: 1, documents_created: 0, documents_updated: 0, chunks_created: 0 }));
  await page.route(/\/api\/v1\/compliance\/ask\/sessions(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [{ id: 'session-1', tenant_id: 'tenant-1', user_id: null, question_hash: 'hash-only-no-question', answer: 'Prior safe answer', citations: [], confidence: 0.8, refused: false, refusal_reason: null, framework_id: framework.id, control_id: control.id, assessment_id: null, retrieval_trace_id: 'trace-1', metadata: {}, created_at: '2026-06-20T12:00:00Z', updated_at: '2026-06-20T12:00:00Z' }], total: 1, skip: 0, limit: 10 }));
}

test('compliance overview renders assessments and gaps without posture overclaims', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await mockComplianceApi(page);
  await page.route(/\/api\/v1\/compliance\/assessments\/run$/, async (route) => fulfillJson(route, assessment));

  await page.goto('/compliance', { waitUntil: 'domcontentloaded' });

  await expect(page.getByText('Evidence-supported posture across frameworks')).toBeVisible();
  await expect(page.getByText('SOC 2')).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Mapping requires human review' })).toBeVisible();
  await expect(page.getByText(/\bcompliant\b/i)).toHaveCount(0);
});

test('framework and control detail render controls, evidence, mappings, gaps, and review mapping', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await mockComplianceApi(page);
  let reviewCalled = false;
  await page.route(`**/api/v1/compliance/mappings/${mapping.id}/review`, async (route) => {
    reviewCalled = true;
    await fulfillJson(route, { ...mapping, review_status: 'approved' });
  });

  await page.goto(`/compliance/frameworks/${framework.id}`, { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Logical access protection')).toBeVisible();
  await page.getByRole('link', { name: /open/i }).click();
  await expect(page.getByText('Mapped findings')).toBeVisible();
  await expect(page.getByText(/normalized .* evidence/i).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Mapping requires human review' })).toBeVisible();
  await page.getByRole('button', { name: /^approve$/i }).click();
  expect(reviewCalled).toBeTruthy();
});

test('evidence library filters and detail drawer avoid raw secret display', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await mockComplianceApi(page);
  let requestedUrl = '';
  await page.route(/\/api\/v1\/compliance\/evidence(?:\?.*)?$/, async (route) => {
    requestedUrl = route.request().url();
    await fulfillJson(route, { items: [evidence], total: 1, skip: 0, limit: 25 });
  });

  await page.goto('/compliance/evidence', { waitUntil: 'domcontentloaded' });
  await page.getByLabel(/source type/i).selectOption('finding_mapping');
  await expect.poll(() => requestedUrl).toContain('source_type=finding_mapping');
  await page.getByRole('button', { name: /detail/i }).click();
  await expect(page.getByLabel('Evidence detail').getByText('Normalized finding evidence')).toBeVisible();
  await expect(page.getByText('super-secret-value')).toHaveCount(0);
  await expect(page.getByText('raw_provider_payload')).toHaveCount(0);
});

test('gaps, recommendations, and knowledge pages render safe metadata without execution controls', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await mockComplianceApi(page);

  await page.goto('/compliance/gaps', { waitUntil: 'domcontentloaded' });
  await page.getByLabel(/severity/i).selectOption('high');
  await expect(page.getByRole('cell', { name: 'Mapping requires human review' })).toBeVisible();

  await page.goto('/compliance/recommendations', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Review needs review')).toBeVisible();
  await expect(page.getByRole('button', { name: /execute|apply/i })).toHaveCount(0);

  await page.goto('/compliance/knowledge', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('SOC2 access control summary')).toBeVisible();
  await expect(page.getByText('summary_only')).toBeVisible();
  await expect(page.getByText('curated', { exact: true })).toBeVisible();
});

test('compliance assistant renders citations and refusal states safely', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await mockComplianceApi(page);
  await page.route(/\/api\/v1\/compliance\/ask$/, async (route) => {
    const body = await route.request().postDataJSON();
    if (String(body.question).includes('guarantee')) {
      await fulfillJson(route, { answer: 'Cannot provide that guarantee.', confidence: 0, citations: [], related_controls: [], related_evidence: [], related_gaps: [], recommended_next_steps: [], refusal_reason: 'legal_guarantee_requested', retrieval_trace_id: null, session_id: 'session-refused' });
      return;
    }
    await fulfillJson(route, { answer: 'Evidence-supported access control posture should be reviewed.', confidence: 0.82, citations: [{ document_title: 'SOC2 access control summary', source_locator: 'control:summary' }], related_controls: [{ control_code: control.control_code }], related_evidence: [{ evidence_id: evidence.id }], related_gaps: [{ gap_id: gap.id }], recommended_next_steps: ['Review mapped evidence with an auditor.'], refusal_reason: null, retrieval_trace_id: 'trace-2', session_id: 'session-2' });
  });

  await page.goto('/compliance/assistant', { waitUntil: 'domcontentloaded' });
  await page.getByLabel(/question/i).fill('What access control evidence should we review?');
  await page.getByRole('button', { name: /^ask$/i }).click();
  await expect(page.getByText('SOC2 access control summary')).toBeVisible();
  await expect(page.getByText('Review mapped evidence')).toBeVisible();

  await page.getByLabel(/question/i).fill('Can you guarantee audit passage?');
  await page.getByRole('button', { name: /^ask$/i }).click();
  await expect(page.getByText(/legal_guarantee_requested/)).toBeVisible();
});

test('read-only compliance role cannot see admin-only actions', async ({ page }) => {
  await mockAuthenticatedUser(page, 'viewer');
  await mockComplianceApi(page);

  await page.goto(`/compliance/controls/${control.id}`, { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Review actions hidden for this role.')).toBeVisible();
  await expect(page.getByRole('button', { name: /^approve$/i })).toHaveCount(0);

  await page.goto('/compliance/knowledge', { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('button', { name: /ingest curated catalog/i })).toBeDisabled();
});

const phase8DemoMappings = [
  mapping,
  {
    ...mapping,
    id: 'dddddddd-dddd-dddd-dddd-ddddddddddde',
    finding_id: '22222222-2222-2222-2222-222222222223',
    rule_id: 'aws_cloudtrail_missing',
    confidence: 0.93,
    control_code: 'SOC2-SEC-MONITOR',
    control_title: 'Monitoring and audit logging',
  },
  {
    ...mapping,
    id: 'dddddddd-dddd-dddd-dddd-dddddddddddf',
    finding_id: '22222222-2222-2222-2222-222222222224',
    rule_id: 'github_secret_exposure',
    confidence: 0.95,
  },
];

const phase8DemoEvidence = [
  {
    ...evidence,
    safe_summary: 'critical active normalized AWS public S3 bucket evidence mapped to SOC2-SEC-ACCESS.',
  },
  {
    ...evidence,
    id: 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeef',
    mapping_id: phase8DemoMappings[1].id,
    finding_id: phase8DemoMappings[1].finding_id,
    safe_summary: 'high active normalized CloudTrail missing evidence mapped to SOC2-SEC-MONITOR.',
  },
  {
    ...evidence,
    id: 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeed',
    mapping_id: phase8DemoMappings[2].id,
    finding_id: phase8DemoMappings[2].finding_id,
    safe_summary: 'critical active normalized GitHub dummy secret exposure evidence mapped safely.',
  },
];

const phase8DemoGaps = [
  {
    ...gap,
    reason: 'Public S3 bucket remains unresolved and caps SOC 2 posture.',
    severity: 'critical',
    gap_type: 'critical_open_risk',
  },
  {
    ...gap,
    id: 'ffffffff-ffff-ffff-ffff-fffffffffffe',
    evidence_id: phase8DemoEvidence[1].id,
    mapping_id: phase8DemoMappings[1].id,
    finding_id: phase8DemoMappings[1].finding_id,
    reason: 'CloudTrail evidence is missing for the primary demo region.',
    severity: 'high',
    gap_type: 'unresolved_finding',
  },
  {
    ...gap,
    id: 'ffffffff-ffff-ffff-ffff-fffffffffffd',
    evidence_id: phase8DemoEvidence[2].id,
    mapping_id: phase8DemoMappings[2].id,
    finding_id: phase8DemoMappings[2].finding_id,
    reason: 'GitHub dummy secret exposure requires human review.',
    severity: 'critical',
    gap_type: 'needs_review',
  },
];

const phase8DemoRecommendations = phase8DemoGaps.map((demoGap, index) => ({
  ...recommendation,
  id: demoGap.id,
  gap_id: demoGap.id,
  finding_id: demoGap.finding_id,
  severity: demoGap.severity,
  title: ['Review public S3 exposure', 'Review CloudTrail logging evidence', 'Review GitHub dummy secret exposure'][index],
  summary: demoGap.reason,
}));

const phase8DemoKnowledge = {
  ...knowledgeDocument,
  title: 'Sprint 3 demo SOC 2 risk narrative',
  source_type: 'demo_acceptance_scenario',
  license_status: 'demo_synthetic',
  trust_level: 'demo_curated',
  metadata: { scenario: 'sprint3_phase8_demo' },
};

async function mockPhase8DemoComplianceApi(page: Page) {
  await mockComplianceApi(page);
  await page.route(/\/api\/v1\/compliance\/mappings(?:\?.*)?$/, async (route) => fulfillJson(route, { items: phase8DemoMappings, total: phase8DemoMappings.length, skip: 0, limit: 100 }));
  await page.route(/\/api\/v1\/compliance\/evidence(?:\?.*)?$/, async (route) => fulfillJson(route, { items: phase8DemoEvidence, total: phase8DemoEvidence.length, skip: 0, limit: 25 }));
  await page.route(/\/api\/v1\/compliance\/gaps(?:\?.*)?$/, async (route) => fulfillJson(route, { items: phase8DemoGaps, total: phase8DemoGaps.length, skip: 0, limit: 25 }));
  await page.route(/\/api\/v1\/compliance\/recommendations(?:\?.*)?$/, async (route) => fulfillJson(route, { items: phase8DemoRecommendations, total: phase8DemoRecommendations.length, skip: 0, limit: 100, status: 'derived_from_existing_gaps' }));
  await page.route(/\/api\/v1\/compliance\/knowledge(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [phase8DemoKnowledge], total: 1, skip: 0, limit: 100 }));
  await page.route(/\/api\/v1\/compliance\/ask$/, async (route) => {
    const body = await route.request().postDataJSON();
    if (String(body.question).toLowerCase().includes('guarantee')) {
      await fulfillJson(route, {
        answer: 'Cannot provide legal guarantees, certification claims, or remediation execution.',
        confidence: 0,
        citations: [],
        related_controls: [],
        related_evidence: [],
        related_gaps: [],
        recommended_next_steps: [],
        refusal_reason: 'legal_guarantee_requested',
        retrieval_trace_id: null,
        session_id: 'phase8-session-refused',
      });
      return;
    }
    await fulfillJson(route, {
      answer: 'SOC 2 is at risk because demo evidence shows a public S3 bucket, missing CloudTrail logging, and GitHub dummy secret exposure. This is evidence-supported posture, not legal advice.',
      confidence: 0.91,
      citations: [{ document_title: phase8DemoKnowledge.title, source_locator: 'demo:sprint3:soc2-risk' }],
      related_controls: [{ control_code: 'SOC2-SEC-ACCESS' }, { control_code: 'SOC2-SEC-MONITOR' }],
      related_evidence: phase8DemoEvidence.map((item) => ({ evidence_id: item.id })),
      related_gaps: phase8DemoGaps.map((item) => ({ gap_id: item.id })),
      recommended_next_steps: ['Review public access evidence.', 'Review CloudTrail logging evidence.', 'Review GitHub secret exposure workflow.'],
      refusal_reason: null,
      retrieval_trace_id: 'phase8-trace',
      session_id: 'phase8-session',
    });
  });
}

test('phase 8 demo acceptance walks compliance console and assistant safely', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await mockPhase8DemoComplianceApi(page);

  await page.goto('/compliance', { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('cell', { name: 'SOC 2', exact: true })).toBeVisible();
  await expect(page.getByText(/\bcompliant\b/i)).toHaveCount(0);

  await page.goto(`/compliance/frameworks/${framework.id}`, { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Logical access protection')).toBeVisible();
  await page.getByRole('link', { name: /open/i }).click();
  await expect(page.getByText('Mapped findings')).toBeVisible();
  await expect(page.getByText(/normalized .* evidence/i).first()).toBeVisible();

  await page.goto('/compliance/evidence', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('public S3 bucket evidence')).toBeVisible();
  await page.getByLabel(/source type/i).selectOption('finding_mapping');

  await page.goto('/compliance/gaps', { waitUntil: 'domcontentloaded' });
  await page.getByLabel(/severity/i).selectOption('critical');
  await expect(page.getByText('Public S3 bucket remains unresolved')).toBeVisible();
  await expect(page.getByText('GitHub dummy secret exposure requires human review')).toBeVisible();

  await page.goto('/compliance/recommendations', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Review CloudTrail logging evidence')).toBeVisible();
  await expect(page.getByRole('button', { name: /execute|apply/i })).toHaveCount(0);

  await page.goto('/compliance/knowledge', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Sprint 3 demo SOC 2 risk narrative')).toBeVisible();
  await expect(page.getByText('demo_synthetic')).toBeVisible();
  await expect(page.getByText('demo curated')).toBeVisible();

  await page.goto('/compliance/assistant', { waitUntil: 'domcontentloaded' });
  await page.getByLabel(/question/i).fill('Why is SOC 2 at risk?');
  await page.getByRole('button', { name: /^ask$/i }).click();
  await expect(page.getByText('public S3 bucket')).toBeVisible();
  await expect(page.getByText('Sprint 3 demo SOC 2 risk narrative')).toBeVisible();
  await expect(page.getByText(/not legal advice/i).first()).toBeVisible();

  await page.getByLabel(/question/i).fill('Can you guarantee we pass audit?');
  await page.getByRole('button', { name: /^ask$/i }).click();
  await expect(page.getByText(/legal_guarantee_requested/)).toBeVisible();

  await expect(page.getByText(/AKIA|ghp_|super-secret|raw_provider_payload|you are compliant/i)).toHaveCount(0);
});

const remediationPlanDraft = {
  id: 'aaaaaaaa-1111-4444-8888-aaaaaaaaaaaa',
  tenant_id: 'tenant-1',
  finding_id: finding.id,
  gap_id: null,
  recommendation_id: null,
  integration_id: integration.id,
  provider: 'aws',
  resource_ref: 'arn:aws:s3:::prod-data',
  risk_level: 'critical',
  status: 'plan_drafted',
  summary: 'Draft plan for public S3 bucket',
  expected_impact: 'Review-only public access reduction draft. No execution is available.',
  created_by: 'user-1',
  created_at: '2026-06-21T10:00:00Z',
  updated_at: '2026-06-21T10:01:00Z',
};

const remediationPlanValidated = {
  ...remediationPlanDraft,
  id: 'bbbbbbbb-1111-4444-8888-bbbbbbbbbbbb',
  status: 'plan_validated',
  risk_level: 'high',
  summary: 'Validated draft plan for CloudTrail logging',
  resource_ref: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/demo',
};

const remediationArtifact = {
  id: 'cccccccc-1111-4444-8888-cccccccccccc',
  tenant_id: 'tenant-1',
  plan_id: remediationPlanDraft.id,
  artifact_type: 'terraform_plan_draft',
  content_redacted: 'NON-EXECUTING DRAFT ONLY. token=super-secret-value raw_provider_payload ghp_supersecretsecretsecretsecret AKIAIOSFODNN7EXAMPLE',
  diff_summary: 'Enable block public access settings for review.',
  artifact_hash: 'artifacthash1234567890',
  risk_flags: { non_executing: true, requires_future_human_approval: true },
  status: 'draft',
  created_at: '2026-06-21T10:00:00Z',
  updated_at: '2026-06-21T10:00:00Z',
};

const remediationPolicyCheck = {
  id: 'dddddddd-1111-4444-8888-dddddddddddd',
  tenant_id: 'tenant-1',
  plan_id: remediationPlanDraft.id,
  artifact_id: remediationArtifact.id,
  passed: false,
  warnings: [{ code: 'public_access_change', message: 'Public access control changes require owner review.' }],
  blocking_reasons: [{ code: 'manual_review_required', message: 'Manual review is required before approval.' }],
  required_approval_level: 'owner',
  policy_check_hash: 'policyhash1234567890',
  created_at: '2026-06-21T10:02:00Z',
  updated_at: '2026-06-21T10:02:00Z',
};

const remediationRollback = {
  id: 'eeeeeeee-1111-4444-8888-eeeeeeeeeeee',
  tenant_id: 'tenant-1',
  plan_id: remediationPlanDraft.id,
  rollback_summary: 'Restore prior reviewed access settings if a future controlled phase executes.',
  rollback_artifact_hash: 'rollbackhash1234567890',
  risk_level: 'critical',
  created_at: '2026-06-21T10:00:00Z',
  updated_at: '2026-06-21T10:00:00Z',
};

const remediationApproval = {
  id: 'ffffffff-1111-4444-8888-ffffffffffff',
  tenant_id: 'tenant-1',
  plan_id: remediationPlanValidated.id,
  artifact_hash: 'validatedartifacthash1234567890',
  policy_check_hash: 'validatedpolicyhash1234567890',
  required_approval_level: 'owner',
  requested_by: 'user-2',
  approved_by: null,
  status: 'pending',
  expires_at: '2026-06-22T10:00:00Z',
  resolved_at: null,
  mfa_verified: false,
  approval_reason: 'Needs owner review.',
  created_at: '2026-06-21T10:03:00Z',
  updated_at: '2026-06-21T10:03:00Z',
};

const remediationJob = {
  id: '99999999-1111-4444-8888-999999999999',
  tenant_id: 'tenant-1',
  plan_id: remediationPlanValidated.id,
  approval_id: remediationApproval.id,
  sandbox_id: 'dryrun-safe-simulated',
  dry_run_result_id: '88888888-1111-4444-8888-888888888888',
  status: 'succeeded',
  disabled_reason: 'Controlled simulated provider execution completed. No external mutation was attempted.',
  started_at: '2026-06-21T10:04:00Z',
  completed_at: '2026-06-21T10:05:00Z',
  created_at: '2026-06-21T10:04:00Z',
  updated_at: '2026-06-21T10:05:00Z',
};

const remediationBlockedJob = {
  id: '99999999-1111-4444-8888-999999999998',
  tenant_id: 'tenant-1',
  plan_id: remediationPlanDraft.id,
  approval_id: null,
  sandbox_id: null,
  dry_run_result_id: null,
  status: 'disabled',
  disabled_reason: 'Blocked mutation demo: Terraform apply, AWS mutation, provider credentials, and shell execution are not allowed.',
  started_at: null,
  completed_at: null,
  created_at: '2026-06-21T10:06:00Z',
  updated_at: '2026-06-21T10:06:00Z',
};

const remediationDryRun = {
  id: remediationJob.dry_run_result_id,
  tenant_id: 'tenant-1',
  job_id: remediationJob.id,
  plan_id: remediationPlanValidated.id,
  artifact_id: remediationArtifact.id,
  approval_id: remediationApproval.id,
  sandbox_id: remediationJob.sandbox_id,
  dry_run_type: 'documentation_only',
  status: 'succeeded',
  output_summary: 'Documentation-only artifact passed static dry-run checks. No execution was attempted.',
  warnings: [],
  blocking_reasons: [],
  started_at: '2026-06-21T10:04:00Z',
  completed_at: '2026-06-21T10:04:30Z',
  created_at: '2026-06-21T10:04:00Z',
  updated_at: '2026-06-21T10:04:30Z',
};

const remediationVerification = {
  id: '77777777-1111-4444-8888-777777777777',
  tenant_id: 'tenant-1',
  plan_id: remediationPlanValidated.id,
  job_id: remediationJob.id,
  finding_status_before: null,
  finding_status_after: 'verified',
  evidence_id: null,
  verified: true,
  verification_summary: 'Simulated provider execution succeeded. No external provider was called and no resources were mutated.',
  status: 'verified',
  created_at: '2026-06-21T10:05:00Z',
  updated_at: '2026-06-21T10:05:00Z',
};

async function mockRemediationApi(page: Page) {
  await page.route(/\/api\/v1\/remediation\/plans(?:\?.*)?$/, async (route) => {
    if (route.request().method() === 'POST') {
      await fulfillJson(route, { ...remediationPlanDraft, artifacts: [remediationArtifact], rollback_plan: remediationRollback, policy_checks: [], approvals: [], execution_jobs: [] });
      return;
    }
    await fulfillJson(route, { items: [remediationPlanDraft, remediationPlanValidated], total: 2, skip: 0, limit: 25 });
  });
  await page.route(`**/api/v1/remediation/plans/${remediationPlanDraft.id}`, async (route) => fulfillJson(route, {
    ...remediationPlanDraft,
    artifacts: [remediationArtifact],
    rollback_plan: remediationRollback,
    policy_checks: [remediationPolicyCheck],
    approvals: [],
    execution_jobs: [],
  }));
  await page.route(`**/api/v1/remediation/plans/${remediationPlanDraft.id}/validate`, async (route) => fulfillJson(route, {
    plan: remediationPlanDraft,
    artifact: remediationArtifact,
    policy_check: remediationPolicyCheck,
  }));
  await page.route(`**/api/v1/remediation/plans/${remediationPlanValidated.id}/request-approval`, async (route) => fulfillJson(route, remediationApproval));
  await page.route(/\/api\/v1\/remediation\/approvals(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [remediationApproval], total: 1, skip: 0, limit: 100 }));
  await page.route(`**/api/v1/remediation/approvals/${remediationApproval.id}/approve`, async (route) => fulfillJson(route, { detail: 'Separation of duties prevents self-approval for elevated remediation' }, 403));
  await page.route(`**/api/v1/remediation/approvals/${remediationApproval.id}/reject`, async (route) => fulfillJson(route, { ...remediationApproval, status: 'rejected', approval_reason: 'Rejected after review.' }));
  await page.route(`**/api/v1/remediation/approvals/${remediationApproval.id}/revoke`, async (route) => fulfillJson(route, { ...remediationApproval, status: 'revoked', approval_reason: 'Revoked stale approval.' }));
  await page.route(/\/api\/v1\/remediation\/dry-runs(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [remediationDryRun], total: 1, skip: 0, limit: 100 }));
  await page.route(/\/api\/v1\/remediation\/verification-results(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [remediationVerification], total: 1, skip: 0, limit: 100 }));
  await page.route(/\/api\/v1\/remediation\/jobs(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [remediationJob, remediationBlockedJob], total: 2, skip: 0, limit: 100 }));
}

test('remediation overview renders safe status without execution controls', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await mockRemediationApi(page);

  await page.goto('/remediation', { waitUntil: 'domcontentloaded' });

  await expect(page.getByText('Remediation Console')).toBeVisible();
  await expect(page.getByText('Controlled safe execution visibility')).toBeVisible();
  await expect(page.getByText('Draft plan for public S3 bucket')).toBeVisible();
  await expect(page.getByText('Validated draft plan for CloudTrail logging')).toBeVisible();
  await expect(page.getByRole('button', { name: /execute|apply|dry-run|terraform/i })).toHaveCount(0);
});

test('remediation plan list filters and request approval flow call safe APIs', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await mockRemediationApi(page);
  let requestedApproval = false;
  await page.route(`**/api/v1/remediation/plans/${remediationPlanValidated.id}/request-approval`, async (route) => {
    requestedApproval = true;
    await fulfillJson(route, remediationApproval);
  });

  await page.goto('/remediation/plans', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Draft plan for public S3 bucket')).toBeVisible();
  await page.getByLabel(/risk level/i).selectOption('critical');
  await page.getByRole('row', { name: /Validated draft plan/ }).getByRole('button', { name: /request approval/i }).click();
  await page.getByLabel(/reason/i).fill('Please review validated draft.');
  await page.getByRole('dialog').getByRole('button', { name: /request approval/i }).click();

  expect(requestedApproval).toBeTruthy();
  await expect(page.getByRole('button', { name: /execute|apply|dry-run|terraform/i })).toHaveCount(0);
});

test('remediation plan detail shows artifact hash, warnings, validation, and no secrets', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await mockRemediationApi(page);
  let validateCalled = false;
  await page.route(`**/api/v1/remediation/plans/${remediationPlanDraft.id}/validate`, async (route) => {
    validateCalled = true;
    await fulfillJson(route, { plan: remediationPlanDraft, artifact: remediationArtifact, policy_check: remediationPolicyCheck });
  });

  await page.goto(`/remediation/plans/${remediationPlanDraft.id}`, { waitUntil: 'domcontentloaded' });

  await expect(page.getByText('Draft only. Not executable from UI.')).toBeVisible();
  await expect(page.getByText('artifacthash1234567890')).toBeVisible();
  await expect(page.getByText('public_access_change')).toBeVisible();
  await expect(page.getByText('manual_review_required')).toBeVisible();
  await page.getByRole('button', { name: /^validate$/i }).click();
  expect(validateCalled).toBeTruthy();
  await expect(page.getByText('super-secret-value')).toHaveCount(0);
  await expect(page.getByText('raw_provider_payload')).toHaveCount(0);
  await expect(page.getByText(/AKIA|ghp_/)).toHaveCount(0);
});

test('remediation approval queue requires reasons and shows backend errors safely', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await mockRemediationApi(page);

  await page.goto('/remediation/approvals', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Validated draft plan for CloudTrail logging')).toBeVisible();

  await page.getByRole('row', { name: /Validated draft plan/ }).getByRole('button', { name: /^approve$/i }).click();
  await expect(page.getByRole('dialog').getByRole('button', { name: /^approve$/i })).toBeDisabled();
  await page.getByLabel(/reason/i).fill('Approving after review.');
  await page.getByLabel(/mfa verified/i).check();
  await page.getByRole('dialog').getByRole('button', { name: /^approve$/i }).click();
  await expect(page.getByText('Separation of duties prevents', { exact: false })).toBeVisible();
  await page.getByRole('dialog').getByRole('button', { name: /^cancel$/i }).click();

  await page.getByRole('row', { name: /Validated draft plan/ }).getByRole('button', { name: /^reject$/i }).click();
  await expect(page.getByRole('dialog').getByRole('button', { name: /^reject$/i })).toBeDisabled();
});

test('remediation jobs are visibility only and expose no mutation controls', async ({ page }) => {
  await mockAuthenticatedUser(page);
  await mockRemediationApi(page);

  await page.goto('/remediation/jobs', { waitUntil: 'domcontentloaded' });

  await expect(page.getByText('Safe simulated/no-op execution records are visible')).toBeVisible();
  await expect(page.getByText('Controlled simulated provider execution completed')).toBeVisible();
  await expect(page.getByText('Documentation-only artifact passed static dry-run checks')).toBeVisible();
  await expect(page.getByText('Simulated provider execution succeeded')).toBeVisible();
  await expect(page.getByText('Blocked mutation demo')).toBeVisible();
  await expect(page.getByRole('button', { name: /execute|apply|dry-run|terraform/i })).toHaveCount(0);
  await expect(page.getByText(/AKIA|ghp_|super-secret|raw_provider_payload/i)).toHaveCount(0);
});

test('read-only remediation role cannot see enabled mutation actions', async ({ page }) => {
  await mockAuthenticatedUser(page, 'viewer');
  await mockRemediationApi(page);

  await page.goto('/remediation/plans', { waitUntil: 'domcontentloaded' });

  await expect(page.getByText('generation, validation, and approval requests are disabled')).toBeVisible();
  await expect(page.getByRole('button', { name: /generate draft/i })).toBeDisabled();
  await expect(page.getByRole('button', { name: /^validate$/i }).first()).toBeDisabled();
  await expect(page.getByRole('button', { name: /request approval/i }).first()).toBeDisabled();

  await page.goto('/remediation/approvals', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('approval decisions are disabled')).toBeVisible();
  await expect(page.getByRole('button', { name: /^approve$/i })).toBeDisabled();
});

const trustPostureBase = {
  tenant_id: 'tenant-1',
  generated_at: '2026-06-22T10:00:00Z',
  language: 'Evidence-supported posture summary for review.',
  posture: 'evidence-supported posture',
  counts: {},
  status_counts: {},
  severity_counts: {},
  freshness: {},
};

const trustSecurityPosture = {
  ...trustPostureBase,
  posture: 'at risk',
  counts: { findings: 4 },
  status_counts: { active: 3, resolved: 1 },
  severity_counts: { critical: 1, high: 2, medium: 1 },
};

const trustCompliancePosture = {
  ...trustPostureBase,
  posture: 'gap detected',
  counts: { mapped_controls: 7, gaps: 2, evidence_items: 8 },
  status_counts: { needs_review: 2, active: 5 },
  freshness: { stale_evidence: 1, fresh_evidence: 7 },
};

const trustRemediationPosture = {
  ...trustPostureBase,
  posture: 'needs review',
  counts: { plans: 3, approvals: 1, verification_results: 2 },
  status_counts: { plan_validated: 1, approval_requested: 1, verified: 1 },
};

const trustIntegrationPosture = {
  ...trustPostureBase,
  counts: { integrations: 2, providers: 3 },
  status_counts: { active: 2 },
  freshness: { last_sync_at: '2026-06-22T09:45:00Z' },
};

const reportTemplate = {
  id: '11111111-aaaa-4444-8888-111111111111',
  tenant_id: 'tenant-1',
  name: 'Quarterly posture package',
  type: 'trust_overview',
  format: 'json',
  filters_schema: { scope: 'executive' },
  default_sections: ['summary', 'posture', 'evidence'],
  created_by: 'user-1',
  created_at: '2026-06-22T10:00:00Z',
  updated_at: '2026-06-22T10:00:00Z',
  is_system: false,
};

const reportArtifact = {
  id: '22222222-aaaa-4444-8888-222222222222',
  tenant_id: 'tenant-1',
  run_id: '33333333-aaaa-4444-8888-333333333333',
  artifact_type: 'trust_report_json',
  content_hash: 'sha256-content-hash-abcdef1234567890',
  size_bytes: 2048,
  sanitization_version: 'export-sanitizer-v1',
  created_at: '2026-06-22T10:01:00Z',
  expires_at: '2026-09-20T10:01:00Z',
  manifest_hash: 'sha256-manifest-hash-abcdef1234567890',
};

const reportManifest = {
  id: '44444444-aaaa-4444-8888-444444444444',
  tenant_id: 'tenant-1',
  artifact_id: reportArtifact.id,
  manifest_json: {
    report_type: 'trust_overview',
    fields: ['posture', 'mapped_controls', 'evidence_freshness'],
    sanitizer: 'export-sanitizer-v1',
  },
  manifest_hash: reportArtifact.manifest_hash,
  hash_algorithm: 'sha256',
  created_at: '2026-06-22T10:01:00Z',
};

const reportRun = {
  id: reportArtifact.run_id,
  tenant_id: 'tenant-1',
  template_id: reportTemplate.id,
  requested_by: 'user-1',
  status: 'completed',
  filters: { report_type: 'trust_overview', scope: 'executive' },
  started_at: '2026-06-22T10:00:00Z',
  completed_at: '2026-06-22T10:01:00Z',
  failed_reason: null,
  expires_at: '2026-09-20T10:01:00Z',
  artifacts: [reportArtifact],
  manifest_hash: reportArtifact.manifest_hash,
};

const evidencePackageRun = {
  ...reportRun,
  id: '55555555-aaaa-4444-8888-555555555555',
  template_id: null,
  filters: { report_type: 'evidence_package', filters: { include_findings: true, include_remediation: true } },
};

const reportAccessLog = {
  id: '66666666-aaaa-4444-8888-666666666666',
  tenant_id: 'tenant-1',
  artifact_id: reportArtifact.id,
  actor_user_id: 'user-1',
  external_share_id: null,
  action: 'viewed',
  ip_hash: 'ip_hash_abc123',
  user_agent_hash: 'ua_hash_def456',
  created_at: '2026-06-22T10:03:00Z',
};

const trustNotification = {
  id: '99999999-aaaa-4444-8888-999999999999',
  tenant_id: 'tenant-1',
  recipient_user_id: 'user-1',
  type: 'report_run_completed',
  severity: 'info',
  title: 'Report run completed',
  body: 'Evidence-supported posture package needs review.',
  resource_type: 'report_run',
  resource_id: reportRun.id,
  read_at: null,
  created_at: '2026-06-22T10:05:00Z',
};

const activityTimeline = [
  {
    id: 'report:artifact:downloaded',
    tenant_id: 'tenant-1',
    occurred_at: '2026-06-22T10:06:00Z',
    source: 'report',
    action: 'downloaded',
    severity: 'info',
    actor_user_id: 'user-1',
    resource_type: 'report_artifact',
    resource_id: reportArtifact.id,
    title: 'Report artifact downloaded',
    summary: 'Metadata-only report access event.',
    metadata: { ip_hash: 'ip_hash_abc123', user_agent_hash: 'ua_hash_def456' },
  },
  {
    id: 'remediation:approval:approved',
    tenant_id: 'tenant-1',
    occurred_at: '2026-06-22T10:04:00Z',
    source: 'remediation',
    action: 'approval_approved',
    severity: 'info',
    actor_user_id: 'user-1',
    resource_type: 'remediation_approval',
    resource_id: remediationApproval.id,
    title: 'Remediation approval approved',
    summary: 'Human approval state changed for a remediation plan.',
    metadata: { plan_id: remediationPlanValidated.id, mfa_verified: true },
  },
  {
    id: 'evidence:item:active',
    tenant_id: 'tenant-1',
    occurred_at: '2026-06-22T10:02:00Z',
    source: 'evidence',
    action: 'evidence_active',
    severity: 'info',
    actor_user_id: null,
    resource_type: 'evidence_item',
    resource_id: evidence.id,
    title: 'Evidence active',
    summary: 'Mapped control evidence needs review.',
    metadata: { proof_hash: 'abcdef1234567890' },
  },
  {
    id: 'integration:health:active',
    tenant_id: 'tenant-1',
    occurred_at: '2026-06-22T10:01:00Z',
    source: 'integration',
    action: 'integration_active',
    severity: 'info',
    actor_user_id: null,
    resource_type: 'cloud_integration',
    resource_id: integration.id,
    title: 'Integration active',
    summary: 'aws integration health updated.',
    metadata: { provider_type: 'aws', status: 'active' },
  },
];

async function mockTrustReportApi(page: Page) {
  await page.route(/\/api\/v1\/trust\/overview$/, async (route) => fulfillJson(route, {
    tenant_id: 'tenant-1',
    generated_at: '2026-06-22T10:00:00Z',
    language: 'Evidence-supported posture summary for review.',
    security_posture: trustSecurityPosture,
    compliance_posture: trustCompliancePosture,
    remediation_posture: trustRemediationPosture,
    integration_health: trustIntegrationPosture,
  }));
  await page.route(/\/api\/v1\/trust\/security-posture$/, async (route) => fulfillJson(route, trustSecurityPosture));
  await page.route(/\/api\/v1\/trust\/compliance-posture$/, async (route) => fulfillJson(route, trustCompliancePosture));
  await page.route(/\/api\/v1\/trust\/remediation-posture$/, async (route) => fulfillJson(route, trustRemediationPosture));
  await page.route(/\/api\/v1\/trust\/integration-health$/, async (route) => fulfillJson(route, trustIntegrationPosture));
  await page.route(/\/api\/v1\/trust\/audit-export-verification-states$/, async (route) => fulfillJson(route, {
    generated_at: '2026-06-22T10:00:00Z',
    language: 'review states only',
    states: [
      { state: 'Verified', severity: 'info', meaning: 'Package verification succeeded.' },
      { state: 'Tampered', severity: 'critical', meaning: 'Package content changed.' },
    ],
  }));
  await page.route(/\/api\/v1\/trust\/activity(?:\?.*)?$/, async (route) => fulfillJson(route, { items: activityTimeline, total: activityTimeline.length, skip: 0, limit: 50 }));
  await page.route(/\/api\/v1\/trust\/notifications\/unread-count$/, async (route) => fulfillJson(route, { unread: 1 }));
  await page.route(`**/api/v1/trust/notifications/${trustNotification.id}/read`, async (route) => fulfillJson(route, { ...trustNotification, read_at: '2026-06-22T10:07:00Z' }));
  await page.route(/\/api\/v1\/trust\/notifications\/mark-all-read$/, async (route) => fulfillJson(route, { unread: 0 }));
  await page.route(/\/api\/v1\/trust\/notifications(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [trustNotification], total: 1, unread: 1, skip: 0, limit: 50 }));
  await page.route(`**/api/v1/reports/artifacts/${reportArtifact.id}/manifest`, async (route) => fulfillJson(route, reportManifest));
  await page.route(`**/api/v1/reports/artifacts/${reportArtifact.id}/download`, async (route) => fulfillJson(route, {
    artifact_id: reportArtifact.id,
    tenant_id: 'tenant-1',
    requester_id: 'user-1',
    external_share_id: null,
    downloaded_at: '2026-06-22T10:04:00Z',
    manifest_hash: reportArtifact.manifest_hash,
    content_type: 'application/json',
    watermark: {
      tenant_id: 'tenant-1',
      requester_id: 'user-1',
      artifact_id: reportArtifact.id,
      downloaded_at: '2026-06-22T10:04:00Z',
      manifest_hash: reportArtifact.manifest_hash,
      language: 'evidence-supported posture; needs review',
    },
    artifact: {
      metadata: { report_type: 'trust_overview' },
      hidden_from_preview: 'token=super-secret-value raw_provider_payload AKIAIOSFODNN7EXAMPLE ghp_supersecretsecretsecretsecret',
    },
  }));
  await page.route(/\/api\/v1\/reports\/templates(?:\?.*)?$/, async (route) => {
    if (route.request().method() === 'POST') {
      await fulfillJson(route, { ...reportTemplate, id: '77777777-aaaa-4444-8888-777777777777', name: 'Board posture review' }, 201);
      return;
    }
    await fulfillJson(route, { items: [reportTemplate], total: 1, skip: 0, limit: 50 });
  });
  await page.route(`**/api/v1/reports/templates/${reportTemplate.id}`, async (route) => {
    if (route.request().method() === 'PATCH') {
      await fulfillJson(route, { ...reportTemplate, name: 'Updated posture package' });
      return;
    }
    if (route.request().method() === 'DELETE') {
      await fulfillJson(route, {}, 204);
      return;
    }
    await fulfillJson(route, reportTemplate);
  });
  await page.route(/\/api\/v1\/reports\/run$/, async (route) => fulfillJson(route, reportRun, 201));
  await page.route(/\/api\/v1\/reports\/runs(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [reportRun], total: 1, skip: 0, limit: 50 }));
  await page.route(`**/api/v1/reports/runs/${reportRun.id}`, async (route) => fulfillJson(route, reportRun));
  await page.route(/\/api\/v1\/reports\/artifacts(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [reportArtifact], total: 1, skip: 0, limit: 50 }));
  await page.route(`**/api/v1/reports/artifacts/${reportArtifact.id}`, async (route) => fulfillJson(route, reportArtifact));
  await page.route(/\/api\/v1\/trust\/share-links(?:\?.*)?$/, async (route) => {
    if (route.request().method() === 'POST') {
      await fulfillJson(route, { id: 'share-link-2', tenant_id: 'tenant-1', artifact_id: reportArtifact.id, scope: { artifact_id: reportArtifact.id }, created_by: 'user-1', expires_at: '2026-07-01T10:00:00Z', revoked_at: null, max_downloads: 5, token: 'trust-share-token-once' }, 201);
      return;
    }
    await fulfillJson(route, { items: [{ id: 'share-link-1', tenant_id: 'tenant-1', artifact_id: reportArtifact.id, scope: {}, created_by: 'user-1', expires_at: '2026-07-01T10:00:00Z', revoked_at: null, max_downloads: 5 }], total: 1, skip: 0, limit: 50 });
  });
  await page.route(/\/api\/v1\/evidence-packages(?:\?.*)?$/, async (route) => {
    if (route.request().method() === 'POST') {
      await fulfillJson(route, { run: evidencePackageRun, artifact: reportArtifact, manifest: reportManifest }, 201);
      return;
    }
    await fulfillJson(route, { items: [evidencePackageRun], total: 1, skip: 0, limit: 50 });
  });
  await page.route(`**/api/v1/evidence-packages/${evidencePackageRun.id}`, async (route) => fulfillJson(route, { run: evidencePackageRun, artifact: reportArtifact, manifest: reportManifest }));
  await page.route(/\/api\/v1\/reports\/access-logs(?:\?.*)?$/, async (route) => fulfillJson(route, { items: [reportAccessLog], total: 1, skip: 0, limit: 50 }));
}

test('trust center pages render posture summaries without legal overclaim copy or secrets', async ({ page }) => {
  await mockAuthenticatedUser(page, 'viewer');
  await mockTrustReportApi(page);

  await page.goto('/trust', { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('heading', { name: 'Trust Center' })).toBeVisible();
  await expect(page.getByText('evidence-supported posture').first()).toBeVisible();
  await expect(page.getByText('Mapped controls', { exact: true })).toBeVisible();
  await expect(page.getByText('needs review').first()).toBeVisible();

  for (const path of ['/trust/security', '/trust/compliance', '/trust/remediation', '/trust/integrations']) {
    await page.goto(path, { waitUntil: 'domcontentloaded' });
    await expect(page.getByText(/last updated/i).first()).toBeVisible();
    await expect(page.getByText(/Status counts|Evidence freshness|Severity counts/).first()).toBeVisible();
  }

  await expect(page.getByText(/legally compliant|certified|guaranteed|audit-ready guaranteed|AKIA|ghp_|super-secret|raw_provider_payload/i)).toHaveCount(0);
});

test('trust activity timeline renders sanitized enterprise events and filters', async ({ page }) => {
  await mockAuthenticatedUser(page, 'auditor');
  await mockTrustReportApi(page);
  let requestedUrl = '';
  await page.route(/\/api\/v1\/trust\/activity(?:\?.*)?$/, async (route) => {
    requestedUrl = route.request().url();
    await fulfillJson(route, { items: activityTimeline, total: activityTimeline.length, skip: 0, limit: 50 });
  });

  await page.goto('/trust/activity', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Activity timeline')).toBeVisible();
  await expect(page.getByText('Report artifact downloaded')).toBeVisible();
  await expect(page.getByText('Remediation approval approved')).toBeVisible();
  await expect(page.getByText('Mapped control evidence needs review.')).toBeVisible();
  await page.getByLabel('Source', { exact: true }).selectOption('report');
  await expect.poll(() => requestedUrl).toContain('source=report');
  await expect(page.getByText('ip_hash_abc123')).toBeVisible();
  await expect(page.getByText(/192\.168\.|Mozilla\/5\.0|legally compliant|certified|guaranteed|AKIA|ghp_|super-secret|raw_provider_payload/i)).toHaveCount(0);
  await expect(page.getByRole('button', { name: /share|public/i })).toHaveCount(0);
});

test('notification center lists and marks sanitized notifications read', async ({ page }) => {
  await mockAuthenticatedUser(page, 'viewer');
  let markReadCalled = false;
  await mockTrustReportApi(page);
  await page.route(`**/api/v1/trust/notifications/${trustNotification.id}/read`, async (route) => {
    markReadCalled = true;
    await fulfillJson(route, { ...trustNotification, read_at: '2026-06-22T10:07:00Z' });
  });

  await page.goto('/notifications', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Notification Center')).toBeVisible();
  await expect(page.getByText('Evidence-supported posture package needs review.')).toBeVisible();
  await page.getByRole('button', { name: /mark read/i }).click();
  expect(markReadCalled).toBeTruthy();
  await expect(page.getByText('Notification marked read')).toBeVisible();
  await expect(page.getByText(/raw provider payloads/i)).toBeVisible();
  await expect(page.getByText(/legally compliant|certified|guaranteed|audit-ready guaranteed|AKIA|ghp_|super-secret|raw_provider_payload|vault:\/\//i)).toHaveCount(0);
  await expect(page.getByRole('button', { name: /download|share|public/i })).toHaveCount(0);
});

test('report templates page supports admin create and edit while avoiding share and file actions', async ({ page }) => {
  await mockAuthenticatedUser(page, 'admin');
  await mockTrustReportApi(page);

  await page.goto('/reports/templates', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Quarterly posture package')).toBeVisible();
  await page.getByRole('button', { name: /new template/i }).click();
  await page.getByLabel(/template name/i).fill('Board posture review');
  await page.getByLabel(/default sections/i).fill('summary,posture,evidence');
  await page.getByRole('button', { name: /create template/i }).click();
  await expect(page.getByText('Template created')).toBeVisible();

  await page.getByRole('row', { name: /Quarterly posture package/ }).getByRole('button', { name: /^edit$/i }).click();
  await page.getByLabel(/template name/i).fill('Updated posture package');
  await page.getByRole('button', { name: /save template/i }).click();
  await expect(page.getByText('Template updated')).toBeVisible();
  await expect(page.getByRole('button', { name: /download|share|public/i })).toHaveCount(0);
});

test('report run creation and detail show metadata, artifact hashes, and no raw body', async ({ page }) => {
  await mockAuthenticatedUser(page, 'auditor');
  await mockTrustReportApi(page);

  await page.goto('/reports/runs', { waitUntil: 'domcontentloaded' });
  await page.getByRole('button', { name: /create run/i }).click();
  await page.getByLabel(/template/i).selectOption(reportTemplate.id);
  await page.getByLabel(/scope/i).fill('executive');
  await page.getByRole('dialog').getByRole('button', { name: /create run/i }).click();
  await expect(page.getByText('Report run created')).toBeVisible();
  await expect(page.getByText('sha256-manifest-hash-abcdef1234567890').first()).toBeVisible();
  await expect(page.getByText('metadata only', { exact: true })).toBeVisible();
  await expect(page.getByText(/raw report body|super-secret|raw_provider_payload|AKIA|ghp_/i)).toHaveCount(0);
});

test('artifact manifest download and share flow display safe metadata', async ({ page }) => {
  await mockAuthenticatedUser(page, 'auditor');
  await mockTrustReportApi(page);

  await page.goto('/reports/artifacts', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('sha256-content-hash-abcdef1234567890')).toBeVisible();
  await page.getByRole('button', { name: /manifest/i }).click();
  await expect(page.getByText('sha256-manifest-hash-abcdef1234567890').first()).toBeVisible();
  await expect(page.getByText('export-sanitizer-v1').first()).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: /^download$/i }).click();
  await expect(page.getByText('Sanitized download metadata')).toBeVisible();
  await expect(page.getByText('evidence-supported posture; needs review')).toBeVisible();
  await expect(page.getByText('Raw report body preview remains hidden', { exact: false })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByText(/Shareable Trust Center links/i)).toBeVisible();
  await page.getByRole('button', { name: /^share$/i }).click();
  await expect(page.getByRole('heading', { name: /Trust Center share link created/i })).toBeVisible();
  await expect(page.getByText(/trust-share-token-once/i)).toBeVisible();
  await expect(page.getByText(/super-secret|raw_provider_payload|AKIA|ghp_/i)).toHaveCount(0);
});

test('evidence package builder creates JSON package metadata only', async ({ page }) => {
  await mockAuthenticatedUser(page, 'auditor');
  await mockTrustReportApi(page);

  await page.goto('/reports/evidence-packages', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Evidence package builder')).toBeVisible();
  await page.getByRole('textbox', { name: /^Framework$/i }).fill('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
  await page.getByRole('textbox', { name: /^Controls$/i }).fill('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb');
  await page.getByLabel(/include findings/i).check();
  await page.getByLabel(/include remediation/i).check();
  await page.getByRole('button', { name: /create evidence package/i }).click();
  await expect(page.getByText('Evidence package created')).toBeVisible();
  await expect(page.getByText('metadata only', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: /zip|pdf|download|share/i })).toHaveCount(0);
});

test('access logs display hashed network metadata and RBAC gates viewer report actions', async ({ page }) => {
  await mockAuthenticatedUser(page, 'auditor');
  await mockTrustReportApi(page);

  await page.goto('/reports/access-logs', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('ip_hash_abc123')).toBeVisible();
  await expect(page.getByText('ua_hash_def456')).toBeVisible();
  await expect(page.getByText(/192\.168\.|Mozilla\/5\.0/)).toHaveCount(0);

  await mockAuthenticatedUser(page, 'viewer');
  await mockTrustReportApi(page);
  await page.goto('/reports', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Report Center access requires analyst, auditor, admin, or owner role.')).toBeVisible();
  await page.goto('/trust', { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('heading', { name: 'Trust Center' })).toBeVisible();

  await mockAuthenticatedUser(page, 'analyst');
  await mockTrustReportApi(page);
  await page.goto('/reports/artifacts', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Artifact download controls are hidden for this role.')).toBeVisible();
  await expect(page.getByRole('button', { name: /^download$/i })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /share|public/i })).toHaveCount(0);
});

test('sprint 5 demo acceptance walks trust reporting UX with demo login safely', async ({ page }) => {
  await mockTrustReportApi(page);
  await page.route('**/auth/login', async (route) => {
    if (route.request().method() === 'OPTIONS') {
      await fulfillJson(route, {}, 204);
      return;
    }
    const body = route.request().postDataJSON() as { email: string; password: string };
    expect(body.email).toBe('demo.admin@authclaw-demo.com');
    expect(body.password).toBe('demo-only-password');
    await fulfillJson(route, { access_token: 'sprint5-demo-token', refresh_token: 'sprint5-demo-refresh', token_type: 'bearer' });
  });
  await page.route('**/auth/me', async (route) => fulfillJson(route, {
    id: 'demo-admin-user',
    email: 'demo.admin@authclaw-demo.com',
    first_name: 'Demo',
    last_name: 'Admin',
    tenant_id: 'authclaw-sprint5-demo',
    role: 'owner',
    roles: ['owner'],
  }));

  await page.goto('/login', { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(250);
  await page.locator('input[type="email"]').fill('demo.admin@authclaw-demo.com');
  await page.locator('input[type="password"]').fill('demo-only-password');
  await page.evaluate(() => {
    window.localStorage.setItem('authclaw_tokens', JSON.stringify({ accessToken: 'sprint5-demo-token', refreshToken: 'sprint5-demo-refresh' }));
  });
  await expect
    .poll(() => page.evaluate(() => window.localStorage.getItem('authclaw_tokens')))
    .toContain('sprint5-demo-token');

  await page.goto('/trust', { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('heading', { name: 'Trust Center' })).toBeVisible();
  await expect(page.getByText('evidence-supported posture').first()).toBeVisible();
  await expect(page.getByText('Mapped controls', { exact: true })).toBeVisible();

  for (const path of ['/trust/security', '/trust/compliance', '/trust/remediation', '/trust/integrations']) {
    await page.goto(path, { waitUntil: 'domcontentloaded' });
    await expect(page.getByText(/last updated/i).first()).toBeVisible();
  }

  await page.goto('/reports/runs', { waitUntil: 'domcontentloaded' });
  await page.getByRole('button', { name: /create run/i }).click();
  await page.getByLabel(/template/i).selectOption(reportTemplate.id);
  await page.getByLabel(/scope/i).fill('sprint5-demo');
  await page.getByRole('dialog').getByRole('button', { name: /create run/i }).click();
  await expect(page.getByText('Report run created')).toBeVisible();
  await expect(page.getByText('sha256-manifest-hash-abcdef1234567890').first()).toBeVisible();

  await page.goto('/reports/artifacts', { waitUntil: 'domcontentloaded' });
  await page.getByRole('button', { name: /manifest/i }).click();
  await expect(page.getByText('sha256-manifest-hash-abcdef1234567890').first()).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: /^download$/i }).click();
  await expect(page.getByText('Sanitized download metadata')).toBeVisible();
  await expect(page.getByText('evidence-supported posture; needs review')).toBeVisible();

  await page.goto('/reports/evidence-packages', { waitUntil: 'domcontentloaded' });
  await page.getByRole('textbox', { name: /^Framework$/i }).fill('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
  await page.getByRole('textbox', { name: /^Controls$/i }).fill('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb');
  await page.getByLabel(/include findings/i).check();
  await page.getByLabel(/include remediation/i).check();
  await page.getByRole('button', { name: /create evidence package/i }).click();
  await expect(page.getByText('Evidence package created')).toBeVisible();
  await expect(page.getByText('metadata only', { exact: true })).toBeVisible();

  await page.goto('/reports/access-logs', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('ip_hash_abc123')).toBeVisible();
  await expect(page.getByText('ua_hash_def456')).toBeVisible();

  await page.goto('/notifications', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Evidence-supported posture package needs review.')).toBeVisible();
  await page.getByRole('button', { name: /^mark read$/i }).click();
  await expect(page.getByText('Notification marked read')).toBeVisible();
  await page.getByRole('button', { name: /mark all read/i }).click();
  await expect(page.getByText('Notifications marked read')).toBeVisible();

  await page.goto('/trust/activity', { waitUntil: 'domcontentloaded' });
  await expect(page.getByText('Activity timeline')).toBeVisible();
  await expect(page.getByText('Report artifact downloaded')).toBeVisible();
  await expect(page.getByText('Mapped control evidence needs review.')).toBeVisible();

  await expect(page.getByRole('button', { name: /share|public/i })).toHaveCount(0);
  await expect(page.getByText(/legally compliant|fully compliant|certified|guaranteed|audit-ready|AKIA|ghp_|super-secret|raw_provider_payload|vault:\/\//i)).toHaveCount(0);
});
