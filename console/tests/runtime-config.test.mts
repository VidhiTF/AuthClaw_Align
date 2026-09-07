import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const route = fs.readFileSync(path.join(root, "src/app/api/runtime-config/route.ts"), "utf8");
const connect = fs.readFileSync(path.join(root, "src/app/(console)/connect/page.tsx"), "utf8");
const settings = fs.readFileSync(path.join(root, "src/app/(console)/settings/page.tsx"), "utf8");

test("public browser URLs come from server runtime configuration", () => {
  assert.match(route, /process\.env\[name\]/);
  assert.match(route, /AUTHCLAW_ENV === "production"/);
  assert.match(route, /must use https:\/\//);
  assert.match(route, /"Cache-Control": "no-store"/);
  assert.doesNotMatch(connect, /process\.env\.NEXT_PUBLIC_GATEWAY_URL/);
  assert.doesNotMatch(settings, /process\.env\.NEXT_PUBLIC_API_URL/);
});
