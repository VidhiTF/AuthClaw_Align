import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "crypto";
import fs from "fs";
import path from "path";

// Keep session state outside src to prevent hot-reload loops and allow
// production containers to point at a known writable location.
const SESSIONS_FILE =
  process.env.AUTHCLAW_SESSION_STORE_PATH ||
  path.join(/* turbopackIgnore: true */ process.cwd(), ".authclaw", "sessions.json");

export interface SessionData {
  sessionId: string;
  userId: string;
  tenantId: string;
  scopes: string[];
  role: string;
  apiKey: string;
  createdAt: number;
}

type StoredSessionData = Omit<SessionData, "apiKey"> & {
  credentialCiphertext: string;
};

type SessionFileData = Record<string, StoredSessionData | SessionData>;

const CREDENTIAL_CIPHER_VERSION = "v1";

function sessionCredentialKey(): Buffer {
  const secret = process.env.SESSION_SECRET;
  if (!secret && process.env.NODE_ENV === "production") {
    throw new Error("SESSION_SECRET is required to encrypt console session credentials");
  }
  return createHash("sha256").update(secret || "authclaw-local-session-secret").digest();
}

function encryptCredential(value: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", sessionCredentialKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    CREDENTIAL_CIPHER_VERSION,
    iv.toString("base64url"),
    tag.toString("base64url"),
    ciphertext.toString("base64url"),
  ].join(".");
}

function decryptCredential(value: string): string {
  const [version, iv, tag, ciphertext] = value.split(".");
  if (version !== CREDENTIAL_CIPHER_VERSION || !iv || !tag || !ciphertext) {
    throw new Error("Unsupported encrypted session credential");
  }
  const decipher = createDecipheriv(
    "aes-256-gcm",
    sessionCredentialKey(),
    Buffer.from(iv, "base64url")
  );
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

function toStoredSession(session: SessionData): StoredSessionData {
  const { apiKey, ...rest } = session;
  return {
    ...rest,
    credentialCiphertext: encryptCredential(apiKey),
  };
}

function fromStoredSession(session: StoredSessionData | SessionData): { session: SessionData; migrated: boolean } {
  if ("credentialCiphertext" in session) {
    return {
      session: {
        ...session,
        apiKey: decryptCredential(session.credentialCiphertext),
      },
      migrated: false,
    };
  }
  return { session, migrated: true };
}

export class SessionStore {
  private readSessions(): { sessions: Map<string, SessionData>; needsRewrite: boolean } {
    try {
      if (fs.existsSync(/* turbopackIgnore: true */ SESSIONS_FILE)) {
        const content = fs.readFileSync(/* turbopackIgnore: true */ SESSIONS_FILE, "utf-8");
        const obj = JSON.parse(content) as SessionFileData;
        let needsRewrite = false;
        const sessions = new Map<string, SessionData>();
        for (const [sessionId, storedSession] of Object.entries(obj)) {
          const restored = fromStoredSession(storedSession);
          sessions.set(sessionId, restored.session);
          needsRewrite = needsRewrite || restored.migrated;
        }
        return { sessions, needsRewrite };
      }
    } catch (err) {
      console.error("Failed to read sessions file:", err);
    }
    return { sessions: new Map(), needsRewrite: false };
  }

  private writeSessions(sessions: Map<string, SessionData>) {
    const obj = Object.fromEntries(
      Array.from(sessions.entries()).map(([sessionId, session]) => [sessionId, toStoredSession(session)])
    );
    const sessionDir = path.dirname(SESSIONS_FILE);
    const tempFile = path.join(sessionDir, `.sessions-${process.pid}-${Date.now()}.tmp`);

    fs.mkdirSync(sessionDir, { recursive: true });
    fs.writeFileSync(tempFile, JSON.stringify(obj, null, 2), "utf-8");
    fs.renameSync(tempFile, SESSIONS_FILE);
  }

  createSession(data: Omit<SessionData, "sessionId" | "createdAt">): SessionData {
    const sessionId = randomUUID();
    const session: SessionData = {
      ...data,
      sessionId,
      createdAt: Date.now(),
    };
    const { sessions } = this.readSessions();
    sessions.set(sessionId, session);
    this.writeSessions(sessions);
    return session;
  }

  getSession(sessionId: string): SessionData | undefined {
    const { sessions, needsRewrite } = this.readSessions();
    const session = sessions.get(sessionId);
    if (!session) return undefined;

    // Check TTL (e.g. 24 hours)
    const oneDay = 24 * 60 * 60 * 1000;
    if (Date.now() - session.createdAt > oneDay) {
      console.warn(JSON.stringify({
        tenant_id: session.tenantId,
        actor_id: session.userId,
        action: "auth:session_expired",
        result: "failure",
        reason: "expired_session",
        request_correlation_id: "",
      }));
      sessions.delete(sessionId);
      this.writeSessions(sessions);
      return undefined;
    }

    if (needsRewrite) {
      this.writeSessions(sessions);
    }

    return session;
  }

  deleteSession(sessionId: string): boolean {
    const { sessions } = this.readSessions();
    const deleted = sessions.delete(sessionId);
    if (deleted) {
      this.writeSessions(sessions);
    }
    return deleted;
  }
}

export const sessionStore = new SessionStore();
