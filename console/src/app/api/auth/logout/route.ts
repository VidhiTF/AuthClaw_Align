import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { sessionStore } from "@/lib/session-store";
import { sessionCookieOptions } from "@/lib/cookie-options";

export async function POST() {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get("authclaw_session")?.value;

  if (sessionToken) {
    try {
      const sessionPayload = JSON.parse(sessionToken);
      if (sessionPayload.sessionId) {
        sessionStore.deleteSession(sessionPayload.sessionId);
      }
    } catch {
      // ignore parsing error
    }
  }

  const response = NextResponse.json({ success: true });

  // Delete the session cookie
  response.cookies.set("authclaw_session", "", {
    ...sessionCookieOptions(),
    expires: new Date(0),
  });

  return response;
}
