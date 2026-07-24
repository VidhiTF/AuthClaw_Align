import { expect, test } from "@playwright/test";

const TENANT_ID = "11111111-1111-4111-8111-111111111111";
const USER_ID = "22222222-2222-4222-8222-222222222222";

async function json<T>(response: import("@playwright/test").APIResponse): Promise<T> {
  expect(response.ok(), await response.text()).toBeTruthy();
  return response.json() as Promise<T>;
}

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

test("authenticated privacy and compliance golden path", async ({ page }) => {
  await login(page);
  const request = page.request;

  const session = await json<{ user: { tenantId: string } }>(await request.get("/api/auth/session"));
  expect(session.user.tenantId).toBe(TENANT_ID);

  const gatewayHeaders = {
    Authorization: `Bearer ${process.env.AUTHCLAW_LITE_DEMO_KEY || "acl_lite_demo_key"}`,
    "Content-Type": "application/json",
    "X-Provider": "gemini",
  };
  const redactionRequestId = `f17-redact-${Date.now()}`;
  const redacted = await request.post(
    "http://127.0.0.1:8080/v1/models/gemini-2.5-flash-lite:generateContent",
    {
      headers: { ...gatewayHeaders, "X-Request-ID": redactionRequestId },
      data: { contents: [{ parts: [{ text: "Contact golden-path@example.com with the result." }] }] },
    },
  );
  expect(redacted.ok(), await redacted.text()).toBeTruthy();

  await expect.poll(async () => {
    const audit = await json<{ records: Array<{ request_id?: string; execution_trace?: unknown }> }>(
      await request.get("/api/audit?limit=100"),
    );
    return String(audit.records.find((record) => record.request_id === redactionRequestId)?.execution_trace || "");
  }, { timeout: 15_000 }).toContain("result=redacted");

  const approvalRequestId = `f17-approval-${Date.now()}`;
  const pendingGatewayRequest = request.post(
    "http://127.0.0.1:8080/v1/models/gemini-2.5-flash-lite:generateContent",
    {
      headers: { ...gatewayHeaders, "X-Request-ID": approvalRequestId },
      data: { contents: [{ parts: [{ text: "Prepare a safe response about a patient diagnosis." }] }] },
      timeout: 40_000,
    },
  );
  let approval: { id: string; action_payload: Record<string, unknown>; status: string } | undefined;
  await expect.poll(async () => {
    const approvals = await json<Array<{ id: string; action_payload: Record<string, unknown>; status: string }>>(
      await request.get("/api/approvals"),
    );
    approval = approvals.find((item) => item.action_payload.request_id === approvalRequestId);
    return approval?.status;
  }, { timeout: 15_000 }).toBe("PENDING");
  expect(approval?.action_payload).toMatchObject({ request_id: approvalRequestId });

  const approved = await json<{ status: string }>(
    await request.post(`/api/approvals/${approval!.id}/approve`, { data: {} }),
  );
  expect(approved.status).toBe("APPROVED");
  expect((await pendingGatewayRequest).ok()).toBeTruthy();

  const exportArtifact = await json<Record<string, unknown>>(
    await request.post("/api/audit/export", { data: { framework: "SOC2" } }),
  );
  const exportVerification = await json<{ verified: boolean; signature_valid: boolean; record_count: number }>(
    await request.post("/api/audit/export/verify", { data: { artifact: exportArtifact } }),
  );
  expect(exportVerification).toMatchObject({ verified: true, signature_valid: true });
  expect(exportVerification.record_count).toBeGreaterThan(0);

  const dsr = await json<{ id: string; status: string }>(
    await request.post("/api/proxy?path=/v1/data-subject-requests", {
      data: { subject_id: USER_ID, request_type: "EXPORT", scope: { systems: ["console"] } },
    }),
  );
  expect(dsr.status).toBe("PENDING");
  expect((await json<{ status: string }>(await request.post(
    `/api/proxy?path=/v1/data-subject-requests/${dsr.id}/verify`,
    { data: { identity_verified: true } },
  ))).status).toBe("VERIFIED");
  expect((await json<{ status: string }>(await request.post(
    `/api/proxy?path=/v1/data-subject-requests/${dsr.id}/approve`,
    { data: { decision_reason: "Golden-path identity and scope verified" } },
  ))).status).toBe("APPROVED");
  const subjectExport = await json<{ request_id: string; manifest: { format_version: string } }>(
    await request.post(`/api/proxy?path=/v1/data-subject-requests/${dsr.id}/export`, { data: {} }),
  );
  expect(subjectExport).toMatchObject({
    request_id: dsr.id,
    manifest: { format_version: "authclaw.data-subject.export.v1" },
  });

  const score = await json<{
    controls: Array<{ traceability: { audit_event_total: number; links: { evidence_url: string } } }>;
  }>(await request.get("/api/compliance-scores/SOC2"));
  expect(score.controls.some((control) =>
    control.traceability.audit_event_total > 0
      && control.traceability.links.evidence_url === "/evidence?framework=SOC2"
  )).toBeTruthy();

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
