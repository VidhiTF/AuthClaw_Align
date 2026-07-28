import { expect, test } from "@playwright/test";
import { createHmac } from "node:crypto";

const TENANT_ID = "11111111-1111-4111-8111-111111111111";
const USER_ID = "22222222-2222-4222-8222-222222222222";
const DELETION_SUBJECT_ID = "22222222-2222-4222-8222-222222222225";
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function totp(secret: string): string {
  const bits = secret.replace(/=+$/, "").toUpperCase().split("").map((character) => {
    const value = BASE32_ALPHABET.indexOf(character);
    if (value < 0) throw new Error("E2E_TOTP_SECRET must be Base32 encoded");
    return value.toString(2).padStart(5, "0");
  }).join("");
  const key = Buffer.from(bits.match(/.{8}/g)?.map((byte) => Number.parseInt(byte, 2)) || []);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const digest = createHmac("sha1", key).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  return ((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
}

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
  const totpSecret = process.env.E2E_TOTP_SECRET;
  expect(totpSecret, "E2E_TOTP_SECRET must be configured for the full-stack MFA user").toBeTruthy();

  const session = await json<{ tenantId: string }>(await request.get("/api/auth/session"));
  expect(session.tenantId).toBe(TENANT_ID);
  const security = await json<{ mfa_enabled: boolean }>(await request.get("/api/users/me/security"));
  expect(security.mfa_enabled).toBe(true);

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
    const audit = await json<{ records: Array<{ request_id?: string; action?: string; execution_trace?: unknown }> }>(
      await request.get("/api/audit?limit=100"),
    );
    return String(audit.records.find((record) =>
      record.request_id === redactionRequestId && record.action === "redact"
    )?.execution_trace || "");
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
    await request.post(`/api/approvals/${approval!.id}/approve`, {
      data: { totp_code: totp(totpSecret!) },
    }),
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

  const deletionRequest = await json<{ id: string; status: string }>(
    await request.post("/api/proxy?path=/v1/data-subject-requests", {
      data: { subject_id: DELETION_SUBJECT_ID, request_type: "DELETION", scope: { systems: ["console"] } },
    }),
  );
  expect((await json<{ status: string }>(await request.post(
    `/api/proxy?path=/v1/data-subject-requests/${deletionRequest.id}/verify`,
    { data: { identity_verified: true } },
  ))).status).toBe("VERIFIED");
  expect((await json<{ status: string }>(await request.post(
    `/api/proxy?path=/v1/data-subject-requests/${deletionRequest.id}/approve`,
    { data: { decision_reason: "Golden-path deletion approved" } },
  ))).status).toBe("APPROVED");
  const deletion = await json<{ request_id: string; completed_at: string }>(
    await request.post(`/api/proxy?path=/v1/data-subject-requests/${deletionRequest.id}/delete`, { data: {} }),
  );
  expect(deletion.request_id).toBe(deletionRequest.id);
  expect(deletion.completed_at).toBeTruthy();
  await expect.poll(async () => {
    const audit = await json<{ records: Array<{ request_id?: string; action?: string }> }>(
      await request.get("/api/audit?limit=100"),
    );
    return audit.records.some((record) =>
      record.request_id === deletionRequest.id && record.action === "deletion_completed"
    );
  }).toBeTruthy();

  const redTeamRun = await json<{ run: { workflow_id: string } }>(
    await request.post("/api/red-team", { data: { observed_responses: {}, simulation_only: true } }),
  );
  const evidence = await json<{
    items: Array<{ id: string; workflow_id: string; framework: string }>;
  }>(await request.get("/api/evidence?page_size=100"));
  const evidenceRecord = evidence.items.find((item) => item.workflow_id === redTeamRun.run.workflow_id);
  expect(evidenceRecord?.id).toBeTruthy();
  const retrievedEvidence = await json<{ id: string; workflow_id: string; framework: string }>(
    await request.get(`/api/evidence/${evidenceRecord!.id}`),
  );
  expect(retrievedEvidence).toMatchObject({
    id: evidenceRecord!.id,
    workflow_id: redTeamRun.run.workflow_id,
    framework: "RED_TEAM",
  });

  const score = await json<{
    controls: Array<{ id: string; traceability: { audit_event_total: number; links: { evidence_url: string } } }>;
  }>(await request.get("/api/compliance-scores/SOC2"));
  const evidenceLinkedControl = score.controls.find((control) =>
    control.traceability.audit_event_total > 0
      && control.traceability.links.evidence_url === "/evidence?framework=SOC2"
  );
  expect(evidenceLinkedControl?.id).toBeTruthy();

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

test("ACL-17 warn is configurable in the policy UI and control-plane API", async ({ page }) => {
  await login(page);
  await page.goto("/policies");

  const warnOptions = page.locator('select option[value="warn"]');
  expect(await warnOptions.count()).toBeGreaterThan(0);
  await expect(warnOptions.first()).toHaveText("Warn, redact, and pass");

  const warnPolicyYaml = `
regex_rules:
  - name: employee_email_warning
    pattern: '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}'
    reason: 'Employee email is redacted and recorded as a warning.'
    severity: medium
    action: warn
model_rules:
  whitelist: [gemini-2.5-flash-lite]
  blacklist: []
topic_rules: []
rate_limits:
  requests_per_minute: 60
`;

  const validation = await json<{ valid: boolean; errors: unknown[] }>(
    await page.request.post("/api/policies/validate", {
      data: { policy_yaml: warnPolicyYaml },
    }),
  );
  expect(validation).toMatchObject({ valid: true, errors: [] });

  const simulation = await json<{
    decision: string;
    allow: boolean;
    matched_rules: Array<{ name?: string; action?: string }>;
  }>(await page.request.post("/api/policies/simulate", {
    data: {
      policy_yaml: warnPolicyYaml,
      model: "gemini-2.5-flash-lite",
      prompts: ["Contact synthetic.employee@example.test"],
      topics: [],
    },
  }));
  expect(simulation).toMatchObject({ decision: "warn", allow: true });
  expect(simulation.matched_rules).toContainEqual(expect.objectContaining({
    name: "employee_email_warning",
    action: "warn",
  }));
});
