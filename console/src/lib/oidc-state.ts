import { createHmac, timingSafeEqual } from "crypto";
import fs from "fs";
import path from "path";
import { sessionKeyRing } from "./session-store.ts";

const STATES_FILE = process.env.AUTHCLAW_OIDC_STATE_STORE_PATH || path.join(/* turbopackIgnore: true */ process.cwd(), ".authclaw", "oidc-states.json");

function readPendingStates(): Record<string, number> {
  try {
    return JSON.parse(fs.readFileSync(/* turbopackIgnore: true */ STATES_FILE, "utf8"));
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

function stateKey(value: string, secret: string) {
  return createHmac("sha256", secret).update(value).digest("base64url");
}

export interface OidcState {
  state: string;
  nonce: string;
  tenantName: string;
  redirectUri: string;
  issuedAt: number;
}

export function sealOidcState(state: OidcState) {
  const { active, keys } = sessionKeyRing();
  const payload = Buffer.from(JSON.stringify(state)).toString("base64url");
  const signature = createHmac("sha256", keys[active]).update(payload).digest("base64url");
  return `${payload}.${active}.${signature}`;
}

export function registerOidcState(value: string) {
  const now = Date.now();
  const states = readPendingStates();
  for (const [key, issuedAt] of Object.entries(states)) {
    if (now - issuedAt > 600_000) delete states[key];
  }
  const { active, keys } = sessionKeyRing();
  states[stateKey(value, keys[active])] = now;
  writePendingStates(states);
}

export function consumeOidcState(value: string) {
  const states = readPendingStates();
  const keys = Object.values(sessionKeyRing().keys);
  const key = keys.map((secret) => stateKey(value, secret)).find((candidate) => states[candidate]);
  const issuedAt = key ? states[key] : undefined;
  if (!issuedAt || Date.now() - issuedAt > 600_000) throw new Error("Invalid OIDC state");
  delete states[key!];
  writePendingStates(states);
}

export function openOidcState(value: string): OidcState {
  const parts = value.split(".");
  const [payload, version, signature] = parts.length === 3 ? parts : [parts[0], "", parts[1]];
  if (!payload || !signature) throw new Error("Invalid OIDC state");
  const actual = Buffer.from(signature, "base64url");
  const { keys } = sessionKeyRing();
  const candidates = version && keys[version] ? [keys[version]] : version ? [] : Object.values(keys);
  if (!candidates.some((secret) => {
    const expected = createHmac("sha256", secret).update(payload).digest();
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  })) {
    throw new Error("Invalid OIDC state");
  }
  const state = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as OidcState;
  if (!state.state || !state.nonce || !state.redirectUri || Date.now() - state.issuedAt > 600_000 || state.issuedAt > Date.now()) {
    throw new Error("Invalid OIDC state");
  }
  return state;
}
