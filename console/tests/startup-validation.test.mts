import assert from "node:assert/strict";
import test from "node:test";

import { sessionCookieOptions } from "../src/lib/cookie-options.ts";
import { register } from "../src/instrumentation.ts";

test("production rejects insecure session cookies", () => {
  const environment = process.env as Record<string, string | undefined>;
  const previousAuthclawEnv = environment.AUTHCLAW_ENV;
  const previousCookieSecure = environment.AUTHCLAW_COOKIE_SECURE;
  environment.AUTHCLAW_ENV = "production";
  environment.AUTHCLAW_COOKIE_SECURE = "false";

  try {
    assert.throws(
      () => register(),
      /AUTHCLAW_COOKIE_SECURE must be true in production/
    );
  } finally {
    if (previousAuthclawEnv === undefined) delete environment.AUTHCLAW_ENV;
    else environment.AUTHCLAW_ENV = previousAuthclawEnv;
    if (previousCookieSecure === undefined) delete environment.AUTHCLAW_COOKIE_SECURE;
    else environment.AUTHCLAW_COOKIE_SECURE = previousCookieSecure;
  }
});

test("local production build allows insecure session cookies", () => {
  const environment = process.env as Record<string, string | undefined>;
  const previousAuthclawEnv = environment.AUTHCLAW_ENV;
  const previousCookieSecure = environment.AUTHCLAW_COOKIE_SECURE;
  environment.AUTHCLAW_ENV = "local";
  environment.AUTHCLAW_COOKIE_SECURE = "false";

  try {
    assert.doesNotThrow(() => register());
  } finally {
    if (previousAuthclawEnv === undefined) delete environment.AUTHCLAW_ENV;
    else environment.AUTHCLAW_ENV = previousAuthclawEnv;
    if (previousCookieSecure === undefined) delete environment.AUTHCLAW_COOKIE_SECURE;
    else environment.AUTHCLAW_COOKIE_SECURE = previousCookieSecure;
  }
});

test("session cookie secure flag honors explicit local override", () => {
  const environment = process.env as Record<string, string | undefined>;
  const previousCookieSecure = environment.AUTHCLAW_COOKIE_SECURE;
  environment.AUTHCLAW_COOKIE_SECURE = "false";

  try {
    assert.equal(sessionCookieOptions().secure, false);
  } finally {
    if (previousCookieSecure === undefined) delete environment.AUTHCLAW_COOKIE_SECURE;
    else environment.AUTHCLAW_COOKIE_SECURE = previousCookieSecure;
  }
});
