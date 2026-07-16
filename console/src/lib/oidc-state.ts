import { createHmac, timingSafeEqual } from "crypto";
import fs from "fs";
import path from "path";

const STATES_FILE = process.env.AUTHCLAW_OIDC_STATE_STORE_PATH || path.join(/* turbopackIgnore: true */ process.cwd(), ".authclaw", "oidc-states.json");

function readPendingStates(): Record<string, number> {
  try {
    return JSON.parse(fs.readFileSync(STATES_FILE, "utf8"));
  } catch {
    return {};
  }
}

function writePendingStates(states: Record<string, number>) {
  fs.mkdirSync(path.dirname(STATES_FILE), { recursive: true });
  const temporary = `${STATES_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(states));
  fs.renameSync(temporary, STATES_FILE);
}

function stateKey(value: string) {
  return createHmac("sha256", stateSecret()).update(value).digest("base64url");
}

export interface OidcState {
  state: string;
  nonce: string;
  tenantName: string;
  redirectUri: string;
  issuedAt: number;
}

function stateSecret() {
  const secret = process.env.SESSION_SECRET;
  if (!secret && process.env.NODE_ENV === "production") {
    throw new Error("SESSION_SECRET is required for OIDC state validation");
  }
  return secret || "authclaw-local-session-secret";
}

export function sealOidcState(state: OidcState) {
  const payload = Buffer.from(JSON.stringify(state)).toString("base64url");
  const signature = createHmac("sha256", stateSecret()).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

export function registerOidcState(value: string) {
  const now = Date.now();
  const states = readPendingStates();
  for (const [key, issuedAt] of Object.entries(states)) {
    if (now - issuedAt > 600_000) delete states[key];
  }
  states[stateKey(value)] = now;
  writePendingStates(states);
}

export function consumeOidcState(value: string) {
  const states = readPendingStates();
  const key = stateKey(value);
  const issuedAt = states[key];
  if (!issuedAt || Date.now() - issuedAt > 600_000) throw new Error("Invalid OIDC state");
  delete states[key];
  writePendingStates(states);
}

export function openOidcState(value: string): OidcState {
  const [payload, signature] = value.split(".");
  if (!payload || !signature) throw new Error("Invalid OIDC state");
  const expected = createHmac("sha256", stateSecret()).update(payload).digest();
  const actual = Buffer.from(signature, "base64url");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new Error("Invalid OIDC state");
  }
  const state = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as OidcState;
  if (!state.state || !state.nonce || !state.redirectUri || Date.now() - state.issuedAt > 600_000 || state.issuedAt > Date.now()) {
    throw new Error("Invalid OIDC state");
  }
  return state;
}
