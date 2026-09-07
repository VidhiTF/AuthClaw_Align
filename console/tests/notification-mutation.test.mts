import assert from "node:assert/strict";
import test from "node:test";

import { performNotificationMutation } from "../src/lib/notification-mutation.ts";

test("notification mutation rejects an unsuccessful backend response", async () => {
  let observedMethod: string | undefined;
  const failedRequest = async (_input: RequestInfo | URL, init?: RequestInit) => {
    observedMethod = init?.method;
    return { ok: false };
  };

  await assert.rejects(
    performNotificationMutation("/api/notifications/read-all", failedRequest),
    /notification update failed/,
  );
  assert.equal(observedMethod, "POST");
});

test("notification mutation resolves only after a successful backend response", async () => {
  let completed = false;
  const successfulRequest = async () => {
    completed = true;
    return { ok: true };
  };

  await performNotificationMutation(
    "/api/notifications/notification-id/read",
    successfulRequest,
  );
  assert.equal(completed, true);
});
