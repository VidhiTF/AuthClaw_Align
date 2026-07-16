import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

async function loadStore(sessionFile: string) {
  process.env.AUTHCLAW_SESSION_STORE_PATH = sessionFile;
  process.env.SESSION_SECRET = "session-store-test-secret-with-enough-entropy";
  const { SessionStore } = await import(`../src/lib/session-store.ts?${Date.now()}-${Math.random()}`);
  return new SessionStore();
}

test("session store encrypts API keys at rest", async () => {
  const sessionDir = fs.mkdtempSync(path.join(os.tmpdir(), "authclaw-session-"));
  const sessionFile = path.join(sessionDir, "sessions.json");
  const store = await loadStore(sessionFile);
  const rawKey = "acl_test_plaintext_secret";

  const session = store.createSession({
    apiKey: rawKey,
    userId: "user-1",
    tenantId: "tenant-1",
    scopes: ["read", "write"],
    role: "owner",
  });

  const stored = fs.readFileSync(sessionFile, "utf8");
  assert.equal(session.apiKey, rawKey);
  assert.equal(stored.includes(rawKey), false);
  assert.equal(stored.includes('"apiKey"'), false);
  assert.equal(stored.includes("credentialCiphertext"), true);
  assert.equal(store.getSession(session.sessionId)?.apiKey, rawKey);
});

test("session store migrates legacy plaintext API keys on read", async () => {
  const sessionDir = fs.mkdtempSync(path.join(os.tmpdir(), "authclaw-session-"));
  const sessionFile = path.join(sessionDir, "sessions.json");
  const store = await loadStore(sessionFile);
  const rawKey = "acl_legacy_plaintext_secret";

  fs.writeFileSync(
    sessionFile,
    JSON.stringify({
      legacy: {
        sessionId: "legacy",
        userId: "user-1",
        tenantId: "tenant-1",
        scopes: ["read"],
        role: "owner",
        apiKey: rawKey,
        createdAt: Date.now(),
      },
    }),
    "utf8"
  );

  assert.equal(store.getSession("legacy")?.apiKey, rawKey);
  const migrated = fs.readFileSync(sessionFile, "utf8");
  assert.equal(migrated.includes(rawKey), false);
  assert.equal(migrated.includes('"apiKey"'), false);
  assert.equal(migrated.includes("credentialCiphertext"), true);
});
