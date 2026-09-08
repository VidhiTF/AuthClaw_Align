import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { sessionCookieName } from "@/lib/cookie-options";
import { sessionCookieOptions } from "@/lib/cookie-options";

export async function POST() {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get(sessionCookieName())?.value;

  if (sessionToken) {
    try {
      await fetch(`${process.env.API_URL || "http://localhost:8000"}/v1/auth/logout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${sessionToken}` },
        cache: "no-store",
      });
    } catch {
      // Always clear the browser cookie even if the backend is unavailable.
    }
  }

  const response = NextResponse.json({ success: true });

  // Delete the session cookie
  response.cookies.set(sessionCookieName(), "", {
    ...sessionCookieOptions(),
    expires: new Date(0),
  });

  return response;
}
