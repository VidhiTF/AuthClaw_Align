import assert from "node:assert/strict";
import test from "node:test";

import { register } from "../src/instrumentation.ts";

test("production rejects insecure session cookies", () => {
  const environment = process.env as Record<string, string | undefined>;
  const previousNodeEnv = environment.NODE_ENV;
  const previousCookieSecure = environment.AUTHCLAW_COOKIE_SECURE;
  environment.NODE_ENV = "production";
  environment.AUTHCLAW_COOKIE_SECURE = "false";

  try {
    assert.throws(
      () => register(),
      /AUTHCLAW_COOKIE_SECURE must be true in production/
    );
  } finally {
    if (previousNodeEnv === undefined) delete environment.NODE_ENV;
    else environment.NODE_ENV = previousNodeEnv;
    if (previousCookieSecure === undefined) delete environment.AUTHCLAW_COOKIE_SECURE;
    else environment.AUTHCLAW_COOKIE_SECURE = previousCookieSecure;
  }
});
