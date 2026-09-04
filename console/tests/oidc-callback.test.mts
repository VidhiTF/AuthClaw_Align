import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = fs.readFileSync(
  path.join(root, "src/app/api/auth/oidc/callback/route.ts"),
  "utf8",
);

test("OIDC callback exposes only the generic authentication failure", () => {
  assert.match(source, /const GENERIC_AUTH_FAILURE = "Authentication failed"/);
  assert.doesNotMatch(source, /data\.(detail|message)/);
  assert.doesNotMatch(source, /error_description/);
  assert.equal((source.match(/return fail\(GENERIC_AUTH_FAILURE\)/g) || []).length, 3);
});

test("OIDC callback sends only opaque state to authenticated exchange and clears failures", () => {
  const binding = source.indexOf("state !== expected");
  const exchange = source.indexOf("await fetch(`${BACKEND_URL}/v1/auth/oidc/callback`");
  const failure = source.indexOf("if (!backendResponse.ok)");
  const session = source.indexOf('response.cookies.set("authclaw_session"');

  assert.ok(binding >= 0 && binding < exchange);
  assert.match(source, /oidcServiceHeaders\("\/v1\/auth\/oidc\/callback", body\)/);
  assert.match(source, /JSON.stringify\(\{ code, transaction_id: expected \}\)/);
  assert.doesNotMatch(source, /nonce:|tenant_name:|redirect_uri:/);
  assert.ok(failure > exchange && failure < session);
  assert.match(source, /const fail = \(message: string\) => \{[\s\S]*response\.cookies\.delete\("authclaw_oidc_state"\)/);
});

test("OIDC callback stores the backend opaque session and redirects", () => {
  assert.match(source, /data\.session_token/);
  assert.doesNotMatch(source, /sessionStore|data\.api_key/);
  assert.match(source, /response\.cookies\.set\("authclaw_session"/);
  assert.match(source, /NextResponse\.redirect\(`\$\{url\.origin\}\/overview`\)/);
});
