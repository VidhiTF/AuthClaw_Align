import assert from "node:assert/strict";
import test from "node:test";

import { oidcStateCookieName, sessionCookieName, sessionCookieOptions } from "../src/lib/cookie-options.ts";

test("cookie names can be isolated by deployment environment", () => {
  const previousSession = process.env.AUTHCLAW_SESSION_COOKIE_NAME;
  const previousOidc = process.env.AUTHCLAW_OIDC_STATE_COOKIE_NAME;
  try {
    process.env.AUTHCLAW_SESSION_COOKIE_NAME = "authclaw_session_stg";
    process.env.AUTHCLAW_OIDC_STATE_COOKIE_NAME = "authclaw_oidc_state_stg";
    assert.equal(sessionCookieName(), "authclaw_session_stg");
    assert.equal(oidcStateCookieName(), "authclaw_oidc_state_stg");

    process.env.AUTHCLAW_SESSION_COOKIE_NAME = "authclaw_session_prod";
    process.env.AUTHCLAW_OIDC_STATE_COOKIE_NAME = "authclaw_oidc_state_prod";
    assert.equal(sessionCookieName(), "authclaw_session_prod");
    assert.equal(oidcStateCookieName(), "authclaw_oidc_state_prod");
  } finally {
    if (previousSession === undefined) delete process.env.AUTHCLAW_SESSION_COOKIE_NAME;
    else process.env.AUTHCLAW_SESSION_COOKIE_NAME = previousSession;
    if (previousOidc === undefined) delete process.env.AUTHCLAW_OIDC_STATE_COOKIE_NAME;
    else process.env.AUTHCLAW_OIDC_STATE_COOKIE_NAME = previousOidc;
  }
});

test("production cookie attributes are host-only and hardened", () => {
  const environment = process.env as Record<string, string | undefined>;
  const previousNodeEnv = environment.NODE_ENV;
  try {
    environment.NODE_ENV = "production";
    const options = sessionCookieOptions(60);
    assert.equal(options.secure, true);
    assert.equal(options.httpOnly, true);
    assert.equal(options.sameSite, "lax");
    assert.equal(options.path, "/");
    assert.equal("domain" in options, false);
  } finally {
    if (previousNodeEnv === undefined) delete environment.NODE_ENV;
    else environment.NODE_ENV = previousNodeEnv;
  }
});
